// Package sniffer implements network traffic sniffing and analysis for CyberRaven
// File: pkg/sniffer/engine.go
package sniffer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"github.com/ajkula/cyberraven/pkg/config"
)

// NetworkEngine handles low-level packet capture and basic filtering
type NetworkEngine struct {
	config *config.SnifferConfig

	// Network configuration
	interfaceName string
	snapLength    int32
	promiscuous   bool
	timeout       time.Duration
	filter        string

	// Capture handle
	handle *pcap.Handle

	// Processing components
	packetSource *gopacket.PacketSource
	assembler    *tcpassembly.Assembler
	factory      *httpStreamFactory
	tlsAnalyzer  *TLSAnalyzer

	// Control channels
	isCapturing int32 // atomic
	stopChan    chan struct{}
	doneChan    chan struct{}

	// Statistics (atomic counters for thread safety)
	packetsProcessed int64
	bytesProcessed   int64
	packetsDropped   int64
	httpPackets      int64
	httpsPackets     int64

	// Error handling
	errors      []error
	errorsMutex sync.Mutex

	// Callbacks for processed data
	httpStreamCallback  func(*HTTPStream)
	httpsStreamCallback func(*HTTPSStream)
	errorCallback       func(error)
}

// HTTPStream represents a reconstructed HTTP stream
type HTTPStream struct {
	ID          string    `json:"id"`
	ClientIP    net.IP    `json:"client_ip"`
	ServerIP    net.IP    `json:"server_ip"`
	ClientPort  int       `json:"client_port"`
	ServerPort  int       `json:"server_port"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	RawRequest  []byte    `json:"raw_request"`
	RawResponse []byte    `json:"raw_response"`
	IsComplete  bool      `json:"is_complete"`
}

// HTTPSStream represents a TLS-encrypted stream (metadata only)
type HTTPSStream struct {
	ID               string    `json:"id"`
	ClientIP         net.IP    `json:"client_ip"`
	ServerIP         net.IP    `json:"server_ip"`
	ClientPort       int       `json:"client_port"`
	ServerPort       int       `json:"server_port"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	TLSVersion       string    `json:"tls_version"`
	CipherSuite      string    `json:"cipher_suite"`
	ServerName       string    `json:"server_name"` // from SNI
	CertFingerprint  string    `json:"cert_fingerprint"`
	BytesTransferred int64     `json:"bytes_transferred"`
}

// NewNetworkEngine creates a new network capture engine
func NewNetworkEngine(config *config.SnifferConfig, interfaceName string) (*NetworkEngine, error) {
	if interfaceName == "" {
		// Auto-detect default interface
		defaultInterface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to detect default interface: %w", err)
		}
		interfaceName = defaultInterface
	}

	// Validate interface exists
	if err := validateInterface(interfaceName); err != nil {
		return nil, fmt.Errorf("invalid interface '%s': %w", interfaceName, err)
	}

	engine := &NetworkEngine{
		config:        config,
		tlsAnalyzer:   NewTLSAnalyzer(true),
		interfaceName: interfaceName,
		snapLength:    65536, // 64KB - capture full packets
		promiscuous:   false, // Only capture traffic to/from this host by default
		timeout:       time.Second * 1,
		filter:        buildDefaultFilter(config),
		stopChan:      make(chan struct{}),
		doneChan:      make(chan struct{}),
		errors:        make([]error, 0),
	}

	// Create stream factory for TCP reassembly
	engine.factory = &httpStreamFactory{
		engine:  engine,
		streams: make(map[string]*httpStream),
	}

	return engine, nil
}

// Start begins packet capture
func (ne *NetworkEngine) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&ne.isCapturing, 0, 1) {
		return fmt.Errorf("capture already in progress")
	}

	// Open capture handle
	handle, err := pcap.OpenLive(ne.interfaceName, ne.snapLength, ne.promiscuous, ne.timeout)
	if err != nil {
		atomic.StoreInt32(&ne.isCapturing, 0)
		return fmt.Errorf("failed to open interface %s: %w", ne.interfaceName, err)
	}

	ne.handle = handle

	// Apply BPF filter
	if ne.filter != "" {
		if err := ne.handle.SetBPFFilter(ne.filter); err != nil {
			ne.handle.Close()
			atomic.StoreInt32(&ne.isCapturing, 0)
			return fmt.Errorf("failed to set BPF filter '%s': %w", ne.filter, err)
		}
	}

	// Create packet source
	ne.packetSource = gopacket.NewPacketSource(ne.handle, ne.handle.LinkType())

	// Create TCP assembler for stream reconstruction
	ne.assembler = tcpassembly.NewAssembler(tcpassembly.NewStreamPool(ne.factory))

	// Start capture goroutine
	go ne.captureLoop(ctx)

	// Start assembler flush timer
	go ne.assemblerFlushLoop(ctx)

	return nil
}

// Stop stops packet capture
func (ne *NetworkEngine) Stop() error {
	if !atomic.CompareAndSwapInt32(&ne.isCapturing, 1, 0) {
		return fmt.Errorf("capture not in progress")
	}

	// Signal stop
	close(ne.stopChan)

	// Wait for capture to complete
	select {
	case <-ne.doneChan:
		// Capture completed
	case <-time.After(5 * time.Second):
		// Timeout waiting for graceful stop
		return fmt.Errorf("timeout waiting for capture to stop")
	}

	// Close handle
	if ne.handle != nil {
		ne.handle.Close()
		ne.handle = nil
	}

	return nil
}

// captureLoop runs the main packet capture loop
func (ne *NetworkEngine) captureLoop(ctx context.Context) {
	defer close(ne.doneChan)
	defer ne.assembler.FlushAll()

	packetChannel := ne.packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ne.stopChan:
			return
		case packet, ok := <-packetChannel:
			if !ok {
				// Channel closed, capture finished
				return
			}

			if packet == nil {
				continue
			}

			// Process packet
			ne.processPacket(packet)
		}
	}
}

// processPacket processes a single captured packet
func (ne *NetworkEngine) processPacket(packet gopacket.Packet) {
	// Update statistics
	atomic.AddInt64(&ne.packetsProcessed, 1)
	atomic.AddInt64(&ne.bytesProcessed, int64(len(packet.Data())))

	// Check for errors in packet
	if err := packet.ErrorLayer(); err != nil {
		ne.recordError(fmt.Errorf("packet error: %v", err.Error()))
		return
	}

	// Extract network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return // Skip non-IP packets
	}

	// Extract transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return // Skip non-TCP/UDP packets
	}

	// Process TCP packets for HTTP/HTTPS stream reconstruction
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		ne.processTCPPacket(packet, tcpLayer.(*layers.TCP))
	}

	// Process UDP packets (for DNS analysis, etc.)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		ne.processUDPPacket(packet, udpLayer.(*layers.UDP))
	}
}

func (ne *NetworkEngine) GetTLSIntelligence() TLSIntelligence {
	if ne.tlsAnalyzer == nil {
		return TLSIntelligence{}
	}
	return ne.tlsAnalyzer.GetTLSIntelligence()
}

// processTCPPacket handles TCP packets for stream reassembly
func (ne *NetworkEngine) processTCPPacket(packet gopacket.Packet, tcp *layers.TCP) {
	// Check if this is HTTP traffic (port 80, 8080, etc.) or HTTPS (port 443, 8443, etc.)
	srcPort := int(tcp.SrcPort)
	dstPort := int(tcp.DstPort)

	isHTTP := ne.isHTTPPort(srcPort) || ne.isHTTPPort(dstPort)
	isHTTPS := ne.isHTTPSPort(srcPort) || ne.isHTTPSPort(dstPort)

	// if !isHTTP && !isHTTPS {
	// 	return // Not HTTP/HTTPS traffic
	// }

	// Update protocol-specific counters

	if isHTTPS {
		atomic.AddInt64(&ne.httpsPackets, 1)
		ne.tlsAnalyzer.ProcessTLSPacket(packet)
	} else if isHTTP {
		atomic.AddInt64(&ne.httpPackets, 1)

		// **CRITICAL ADDITION:** Detect TLS on HTTP ports (like 8080)
		if len(tcp.Payload) >= 3 {
			recordType := tcp.Payload[0]
			tlsVersion := tcp.Payload[1]

			// Check if this is TLS traffic on HTTP port
			if (recordType >= 0x14 && recordType <= 0x17) && tlsVersion == 0x03 {
				fmt.Printf("[DEBUG] TLS detected on HTTP port (type: 0x%02x, version: 0x%02x), calling TLS Analyzer\n",
					recordType, tlsVersion)
				ne.tlsAnalyzer.ProcessTLSPacket(packet)
				return // Don't process as HTTP
			}
		}

		// Normal HTTP processing...
		// Feed packet to TCP assembler for stream reconstruction
		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			ne.assembler.AssembleWithTimestamp(
				networkLayer.NetworkFlow(),
				tcp,
				packet.Metadata().Timestamp,
			)
		}
	}
}

// processUDPPacket handles UDP packets (DNS, etc.)
func (ne *NetworkEngine) processUDPPacket(packet gopacket.Packet, udp *layers.UDP) {
	// For now, we mainly care about DNS for hostname resolution
	if int(udp.DstPort) == 53 || int(udp.SrcPort) == 53 {
		ne.processDNSPacket(packet) // Suppression du paramètre udp
	}
}

// processDNSPacket extracts hostname information from DNS queries
func (ne *NetworkEngine) processDNSPacket(packet gopacket.Packet) {
	// DNS packet processing for hostname resolution
	// This helps correlate IP addresses with hostnames in HTTP traffic
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)

		// Process DNS queries and responses
		for _, question := range dns.Questions {
			hostname := string(question.Name)
			// Store hostname mapping for later correlation
			ne.recordHostnameMapping(hostname, packet.Metadata().Timestamp)
		}

		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA && len(answer.IP) > 0 {
				hostname := string(answer.Name)
				ip := answer.IP
				// Store IP -> hostname mapping
				ne.recordIPHostnameMapping(ip, hostname)
			}
		}
	}
}

// assemblerFlushLoop periodically flushes old connections from the assembler
func (ne *NetworkEngine) assemblerFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute * 1) // Flush every minute
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ne.stopChan:
			return
		case <-ticker.C:
			// Flush connections older than 5 minutes
			ne.assembler.FlushOlderThan(time.Now().Add(-5 * time.Minute))
		}
	}
}

// Helper methods

func (ne *NetworkEngine) isHTTPPort(port int) bool {
	httpPorts := []int{80, 8080, 8000, 3000, 8081, 8008, 9000, 9080}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

func (ne *NetworkEngine) isHTTPSPort(port int) bool {
	httpsPorts := []int{443, 8443, 9443, 8143}
	for _, p := range httpsPorts {
		if port == p {
			return true
		}
	}
	return false
}

func (ne *NetworkEngine) recordError(err error) {
	ne.errorsMutex.Lock()
	ne.errors = append(ne.errors, err)
	ne.errorsMutex.Unlock()

	if ne.errorCallback != nil {
		ne.errorCallback(err)
	}
}

func (ne *NetworkEngine) recordHostnameMapping(hostname string, timestamp time.Time) {
	// Implementation for hostname tracking
	// This would store hostname -> timestamp mapping for analysis
}

func (ne *NetworkEngine) recordIPHostnameMapping(ip net.IP, hostname string) {
	// Implementation for IP -> hostname mapping
	// This helps identify which hostnames correspond to captured traffic
}

// Configuration and setup helpers

func buildDefaultFilter(config *config.SnifferConfig) string {
	filters := []string{}

	// Build filters based on configuration
	if config.CaptureHTTP {
		filters = append(filters, "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 3000")
	}

	if config.CaptureHTTPS {
		filters = append(filters, "tcp port 443 or tcp port 8443")
	}

	if config.CaptureOther {
		// Add DNS for hostname resolution
		filters = append(filters, "udp port 53")
	}

	// Use custom BPF filter if provided
	if config.BPFFilter != "" {
		return config.BPFFilter
	}

	// Combine filters with OR
	if len(filters) > 1 {
		result := ""
		for i, filter := range filters {
			if i == 0 {
				result = "(" + filter + ")"
			} else {
				result += " or (" + filter + ")"
			}
		}
		return result
	} else if len(filters) == 1 {
		return filters[0]
	}

	// Default fallback
	return "tcp port 80 or tcp port 443 or udp port 53"
}

func getDefaultInterface() (string, error) {
	// Sous Windows, utiliser la première interface active trouvée par pcap
	if runtime.GOOS == "windows" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return "", fmt.Errorf("failed to find network devices: %w", err)
		}

		fmt.Printf("Found %d devices:\n", len(devices))
		for _, device := range devices {
			// Chercher une interface active avec une adresse IP
			if len(device.Addresses) > 0 && device.Name != "" {
				// Éviter les interfaces loopback et virtuelles
				if !strings.Contains(device.Description, "Loopback") &&
					!strings.Contains(device.Description, "VMware") &&
					!strings.Contains(device.Description, "VirtualBox") {
					return device.Name, nil
				}
			}
		}
		return "", fmt.Errorf("no suitable network interface found")
	}

	// Code existant pour Linux/macOS
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get interface addresses
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Check if interface has IP address
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

func validateInterface(name string) error {
	// Sous Windows, utiliser pcap pour valider
	if runtime.GOOS == "windows" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("failed to enumerate network devices: %w", err)
		}

		// Chercher par nom exact ou description
		for _, device := range devices {
			if device.Name == name ||
				strings.Contains(device.Description, name) ||
				strings.EqualFold(device.Description, name) {
				return nil
			}
		}

		// Si pas trouvé, lister les interfaces disponibles pour debugging
		var availableInterfaces []string
		for _, device := range devices {
			if device.Description != "" {
				availableInterfaces = append(availableInterfaces, fmt.Sprintf("%s (%s)", device.Name, device.Description))
			} else {
				availableInterfaces = append(availableInterfaces, device.Name)
			}
		}

		return fmt.Errorf("interface '%s' not found. Available interfaces: %v", name, availableInterfaces)
	}

	// Code existant pour Linux/macOS
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			if iface.Flags&net.FlagUp == 0 {
				return fmt.Errorf("interface '%s' is down", name)
			}
			return nil
		}
	}

	return fmt.Errorf("interface '%s' not found", name)
}

// Statistics and monitoring

// GetStats returns current capture statistics
func (ne *NetworkEngine) GetStats() (packetsProcessed, bytesProcessed, packetsDropped, httpPackets, httpsPackets int64) {
	return atomic.LoadInt64(&ne.packetsProcessed),
		atomic.LoadInt64(&ne.bytesProcessed),
		atomic.LoadInt64(&ne.packetsDropped),
		atomic.LoadInt64(&ne.httpPackets),
		atomic.LoadInt64(&ne.httpsPackets)
}

// GetErrors returns captured errors
func (ne *NetworkEngine) GetErrors() []error {
	ne.errorsMutex.Lock()
	defer ne.errorsMutex.Unlock()

	errors := make([]error, len(ne.errors))
	copy(errors, ne.errors)
	return errors
}

// IsCapturing returns whether capture is currently active
func (ne *NetworkEngine) IsCapturing() bool {
	return atomic.LoadInt32(&ne.isCapturing) == 1
}

// Callbacks for processed data

// SetHTTPStreamCallback sets callback for processed HTTP streams
func (ne *NetworkEngine) SetHTTPStreamCallback(callback func(*HTTPStream)) {
	ne.httpStreamCallback = callback
}

// SetHTTPSStreamCallback sets callback for processed HTTPS streams
func (ne *NetworkEngine) SetHTTPSStreamCallback(callback func(*HTTPSStream)) {
	ne.httpsStreamCallback = callback
}

// SetErrorCallback sets callback for capture errors
func (ne *NetworkEngine) SetErrorCallback(callback func(error)) {
	ne.errorCallback = callback
}

// Configuration methods

// SetFilter updates the BPF filter (requires restart of capture)
func (ne *NetworkEngine) SetFilter(filter string) error {
	if ne.IsCapturing() {
		return fmt.Errorf("cannot change filter while capturing")
	}

	ne.filter = filter
	return nil
}

// SetPromiscuous enables/disables promiscuous mode (requires restart)
func (ne *NetworkEngine) SetPromiscuous(promiscuous bool) error {
	if ne.IsCapturing() {
		return fmt.Errorf("cannot change promiscuous mode while capturing")
	}

	ne.promiscuous = promiscuous
	return nil
}

// GetInterface returns the current interface name
func (ne *NetworkEngine) GetInterface() string {
	return ne.interfaceName
}

// GetFilter returns the current BPF filter
func (ne *NetworkEngine) GetFilter() string {
	return ne.filter
}

// Close cleans up resources
func (ne *NetworkEngine) Close() error {
	if ne.IsCapturing() {
		if err := ne.Stop(); err != nil {
			return err
		}
	}

	return nil
}

// TCP Stream Factory for HTTP reconstruction

// httpStreamFactory creates HTTP stream processors for TCP reassembly
type httpStreamFactory struct {
	engine         *NetworkEngine
	streams        map[string]*httpStream
	partialStreams map[string]*HTTPStream
	mu             sync.Mutex
}

// New creates a new HTTP stream for the given TCP flow
func (factory *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	// Normalize stream ID to be consistent regardless of direction
	streamID := normalizeStreamID(net, transport)

	factory.mu.Lock()
	defer factory.mu.Unlock()

	if factory.partialStreams == nil {
		factory.partialStreams = make(map[string]*HTTPStream)
	}

	stream := &httpStream{
		id:        streamID,
		net:       net,
		transport: transport,
		factory:   factory,
		data:      make([]byte, 0),
		startTime: time.Now(),
	}

	factory.streams[streamID] = stream
	return stream
}

// normalizeStreamID creates a consistent stream ID regardless of traffic direction
func normalizeStreamID(net, transport gopacket.Flow) string {
	// Extract IPs and ports
	srcIP := net.Src().String()
	dstIP := net.Dst().String()
	srcPort := transport.Src().String()
	dstPort := transport.Dst().String()

	// Normalize by always putting the "smaller" endpoint first
	// This ensures req (client->server) and res (server->client) have same ID
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		// src is "smaller" - use as-is
		return fmt.Sprintf("%s:%s<->%s:%s", srcIP, srcPort, dstIP, dstPort)
	} else {
		// dst is "smaller" - swap them
		return fmt.Sprintf("%s:%s<->%s:%s", dstIP, dstPort, srcIP, srcPort)
	}
}

// httpStream represents an individual HTTP stream being reconstructed
type httpStream struct {
	id        string
	net       gopacket.Flow
	transport gopacket.Flow
	factory   *httpStreamFactory
	data      []byte
	startTime time.Time
	endTime   time.Time
	mu        sync.Mutex
}

// Reassembled processes reassembled TCP data
func (stream *httpStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	stream.mu.Lock()
	defer stream.mu.Unlock()

	for _, r := range reassembly {
		if len(r.Bytes) > 0 {
			stream.data = append(stream.data, r.Bytes...)
		}
	}

	// Try to parse HTTP data when we have enough
	if len(stream.data) > 100 { // Minimum size for HTTP request/response
		stream.processHTTPData()
	}
}

// ReassemblyComplete is called when the stream is complete
func (stream *httpStream) ReassemblyComplete() {
	stream.mu.Lock()
	defer stream.mu.Unlock()

	stream.endTime = time.Now()

	// Final processing of any remaining data
	if len(stream.data) > 0 {
		stream.processHTTPData()
	}

	// Clean up
	stream.factory.mu.Lock()
	delete(stream.factory.streams, stream.id)
	stream.factory.mu.Unlock()
}

// processHTTPData attempts to parse HTTP requests/responses from stream data
func (stream *httpStream) processHTTPData() {
	data := stream.data

	if len(data) < 4 {
		return
	}

	// Route TLS traffic to TLS Analyzer
	if len(data) >= 3 && data[1] == 0x03 {
		recordType := data[0]
		if recordType >= 0x14 && recordType <= 0x17 {
			return // TLS detected, skip HTTP processing
		}
	}

	dataStr := string(data[:min(len(data), 200)])
	isHTTPRequest := false
	isHTTPResponse := false

	// HTTP request detection
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE "}
	for _, method := range httpMethods {
		if len(dataStr) >= len(method) && dataStr[:len(method)] == method {
			isHTTPRequest = true
			break
		}
	}

	// HTTP response detection
	if !isHTTPRequest && len(dataStr) >= 5 && dataStr[:5] == "HTTP/" {
		isHTTPResponse = true
	}

	if isHTTPRequest || isHTTPResponse {
		// Extract connection info
		var clientIP, serverIP net.IP
		var clientPort, serverPort int

		if stream.net.Src().String() != "" {
			clientIP = net.ParseIP(stream.net.Src().String())
			serverIP = net.ParseIP(stream.net.Dst().String())
		}

		if stream.transport.Src().String() != "" {
			srcPortBytes := stream.transport.Src().Raw()
			dstPortBytes := stream.transport.Dst().Raw()

			if len(srcPortBytes) >= 2 {
				clientPort = int(binary.BigEndian.Uint16(srcPortBytes))
			}
			if len(dstPortBytes) >= 2 {
				serverPort = int(binary.BigEndian.Uint16(dstPortBytes))
			}
		}

		normalizedID := normalizeStreamID(stream.net, stream.transport)

		// Get or create partial stream
		stream.factory.mu.Lock()
		existingStream := stream.factory.partialStreams[normalizedID]

		if existingStream == nil {
			existingStream = &HTTPStream{
				ID:         normalizedID,
				ClientIP:   clientIP,
				ServerIP:   serverIP,
				ClientPort: clientPort,
				ServerPort: serverPort,
				StartTime:  stream.startTime,
				EndTime:    stream.endTime,
			}
			stream.factory.partialStreams[normalizedID] = existingStream
		}

		// Add appropriate data
		if isHTTPRequest {
			existingStream.RawRequest = data
		} else if isHTTPResponse {
			existingStream.RawResponse = data
		}

		// Update timing
		if !stream.endTime.IsZero() {
			existingStream.EndTime = stream.endTime
		}

		// Check if complete
		isComplete := len(existingStream.RawRequest) > 0 && len(existingStream.RawResponse) > 0
		existingStream.IsComplete = isComplete

		stream.factory.mu.Unlock()

		// Send to callback
		if stream.factory.engine.httpStreamCallback != nil {
			stream.factory.engine.httpStreamCallback(existingStream)
		}

		// Cleanup if complete
		if isComplete {
			stream.factory.mu.Lock()
			delete(stream.factory.partialStreams, normalizedID)
			stream.factory.mu.Unlock()
		}
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
