// Package proxy provides MITM proxy capabilities for TLS traffic interception
// This is used when TLS exploitation succeeds and we need to route
// subsequent attacks through the compromised channel
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// MITMProxy represents a Man-in-the-Middle proxy for TLS interception
type MITMProxy struct {
	config     *Config
	listener   net.Listener
	certGen    *CertGenerator

	// State
	mu         sync.RWMutex
	running    bool
	connections int64
	bytesIn    int64
	bytesOut   int64

	// Channels for coordination
	stopChan   chan struct{}
	doneChan   chan struct{}
}

// Config holds the MITM proxy configuration
type Config struct {
	ListenAddr     string        `json:"listen_addr"`
	TargetHost     string        `json:"target_host"`
	TargetPort     string        `json:"target_port"`
	Timeout        time.Duration `json:"timeout"`
	CertPath       string        `json:"cert_path,omitempty"`
	KeyPath        string        `json:"key_path,omitempty"`
	InsecureTarget bool          `json:"insecure_target"` // Skip target cert verification
}

// Stats contains proxy statistics
type Stats struct {
	Running     bool   `json:"running"`
	Connections int64  `json:"connections"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	ListenAddr  string `json:"listen_addr"`
	TargetHost  string `json:"target_host"`
}

// NewMITMProxy creates a new MITM proxy instance
func NewMITMProxy(config *Config) (*MITMProxy, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.ListenAddr == "" {
		config.ListenAddr = "127.0.0.1:8443"
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Create certificate generator
	certGen, err := NewCertGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate generator: %w", err)
	}

	return &MITMProxy{
		config:   config,
		certGen:  certGen,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}, nil
}

// Start starts the MITM proxy
func (p *MITMProxy) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("proxy already running")
	}
	p.running = true
	p.mu.Unlock()

	// Generate certificate for target host
	cert, err := p.certGen.GenerateForHost(p.config.TargetHost)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Create TLS config with our certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	}

	// Start listening
	listener, err := tls.Listen("tcp", p.config.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	p.listener = listener

	// Start accepting connections
	go p.acceptLoop(ctx)

	return nil
}

// Stop stops the MITM proxy
func (p *MITMProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	close(p.stopChan)

	if p.listener != nil {
		p.listener.Close()
	}

	p.running = false

	// Wait for acceptLoop to finish
	select {
	case <-p.doneChan:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for proxy to stop")
	}

	return nil
}

// acceptLoop accepts and handles incoming connections
func (p *MITMProxy) acceptLoop(ctx context.Context) {
	defer close(p.doneChan)

	for {
		select {
		case <-p.stopChan:
			return
		case <-ctx.Done():
			return
		default:
		}

		// Set accept deadline to allow checking stop channel
		if tcpListener, ok := p.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := p.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, check stop channel and try again
			}
			// Real error or listener closed
			return
		}

		p.mu.Lock()
		p.connections++
		p.mu.Unlock()

		go p.handleConnection(ctx, conn)
	}
}

// handleConnection handles a single proxied connection
func (p *MITMProxy) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	// Connect to target
	targetAddr := net.JoinHostPort(p.config.TargetHost, p.config.TargetPort)

	targetTLSConfig := &tls.Config{
		ServerName:         p.config.TargetHost,
		InsecureSkipVerify: p.config.InsecureTarget,
	}

	targetConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: p.config.Timeout},
		"tcp",
		targetAddr,
		targetTLSConfig,
	)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(targetConn, clientConn)
		p.mu.Lock()
		p.bytesOut += n
		p.mu.Unlock()
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		p.mu.Lock()
		p.bytesIn += n
		p.mu.Unlock()
		done <- struct{}{}
	}()

	// Wait for either direction to complete
	select {
	case <-done:
	case <-ctx.Done():
	case <-p.stopChan:
	}
}

// GetStats returns current proxy statistics
func (p *MITMProxy) GetStats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return Stats{
		Running:     p.running,
		Connections: p.connections,
		BytesIn:     p.bytesIn,
		BytesOut:    p.bytesOut,
		ListenAddr:  p.config.ListenAddr,
		TargetHost:  p.config.TargetHost,
	}
}

// GetHTTPClient returns an HTTP client configured to use this proxy
// This allows subsequent attacks to route through the MITM proxy
func (p *MITMProxy) GetHTTPClient() *http.Client {
	// Note: proxyURL would be used for proxy configuration in more complex setups
	// Currently using direct connection redirection
	_ = fmt.Sprintf("https://%s", p.config.ListenAddr)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Trust our MITM cert
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Redirect all connections through our proxy
			return net.DialTimeout("tcp", p.config.ListenAddr, p.config.Timeout)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   p.config.Timeout,
	}
}

// IsRunning returns whether the proxy is currently running
func (p *MITMProxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}
