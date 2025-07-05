// Package sniffer implements network traffic sniffing and analysis for CyberRaven
// File: pkg/sniffer/parser.go
package sniffer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ajkula/cyberraven/pkg/config"
)

// Parser handles HTTP protocol parsing and conversation reconstruction
type Parser struct {
	config *config.SnifferConfig

	// Conversation tracking
	conversations map[string]*HTTPConversation
	mu            sync.RWMutex

	// Parsing components
	requestParser  *RequestParser
	responseParser *ResponseParser

	// Conversation matching
	pendingRequests  map[string]*HTTPRequest  // key: clientIP:clientPort -> request
	pendingResponses map[string]*HTTPResponse // key: serverIP:serverPort -> response
	matchMutex       sync.Mutex

	// Configuration
	maxBodySize    int           // Maximum body size to parse (default 10MB)
	timeout        time.Duration // Conversation timeout
	retainDuration time.Duration // How long to keep completed conversations

	// Statistics
	parsedRequests  int64
	parsedResponses int64
	matchedConvs    int64
	parseErrors     int64

	// Callbacks
	conversationCallback func(*HTTPConversation)
	errorCallback        func(error)

	// Cleanup
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// RequestParser handles HTTP request parsing
type RequestParser struct {
	maxHeaderSize int
	maxBodySize   int
}

// ResponseParser handles HTTP response parsing
type ResponseParser struct {
	maxHeaderSize int
	maxBodySize   int
}

// NewParser creates a new HTTP parser
func NewParser(config *config.SnifferConfig) *Parser {
	parser := &Parser{
		config:           config,
		conversations:    make(map[string]*HTTPConversation),
		pendingRequests:  make(map[string]*HTTPRequest),
		pendingResponses: make(map[string]*HTTPResponse),
		maxBodySize:      10 * 1024 * 1024, // 10MB default
		timeout:          30 * time.Second,
		retainDuration:   5 * time.Minute,
		stopCleanup:      make(chan struct{}),
	}

	// Initialize sub-parsers
	parser.requestParser = &RequestParser{
		maxHeaderSize: 64 * 1024, // 64KB headers max
		maxBodySize:   parser.maxBodySize,
	}

	parser.responseParser = &ResponseParser{
		maxHeaderSize: 64 * 1024, // 64KB headers max
		maxBodySize:   parser.maxBodySize,
	}

	// Start cleanup routine
	parser.cleanupTicker = time.NewTicker(1 * time.Minute)
	go parser.cleanupRoutine()

	return parser
}

// ProcessHTTPStream processes an HTTP stream from the network engine
func (p *Parser) ProcessHTTPStream(stream *HTTPStream) {
	fmt.Printf("STREAM: %+v", stream)
	if stream == nil {
		return
	}

	// Determine if this is a request or response by analyzing the data
	if len(stream.RawRequest) > 0 {
		p.processRawHTTPData(stream, stream.RawRequest)
	}

	if len(stream.RawResponse) > 0 {
		p.processRawHTTPData(stream, stream.RawResponse)
	}
}

// processRawHTTPData determines if data is request or response and parses accordingly
func (p *Parser) processRawHTTPData(stream *HTTPStream, data []byte) {
	if len(data) == 0 {
		return
	}

	// Quick analysis to determine if this is request or response
	firstLine, err := p.extractFirstLine(data)
	if err != nil {
		p.recordError(fmt.Errorf("failed to extract first line: %w", err))
		return
	}

	if p.isHTTPRequest(firstLine) {
		p.processHTTPRequest(stream, data)
	} else if p.isHTTPResponse(firstLine) {
		p.processHTTPResponse(stream, data)
	} else {
		// Unknown HTTP format
		p.recordError(fmt.Errorf("unrecognized HTTP format: %s", firstLine))
	}
}

// processHTTPRequest parses HTTP request data
func (p *Parser) processHTTPRequest(stream *HTTPStream, data []byte) {
	request, err := p.requestParser.Parse(data)
	if err != nil {
		p.recordError(fmt.Errorf("failed to parse HTTP request: %w", err))
		p.parsedRequests++
		return
	}

	// Enrich request with stream metadata
	request.ClientIP = stream.ClientIP
	request.ServerIP = stream.ServerIP
	request.ClientPort = stream.ClientPort
	request.ServerPort = stream.ServerPort
	request.Timestamp = stream.StartTime

	p.parsedRequests++

	// Try to match with pending response or store for later matching
	p.matchRequest(request)
}

// processHTTPResponse parses HTTP response data
func (p *Parser) processHTTPResponse(stream *HTTPStream, data []byte) {
	response, err := p.responseParser.Parse(data)
	if err != nil {
		p.recordError(fmt.Errorf("failed to parse HTTP response: %w", err))
		p.parseErrors++
		return
	}

	// Enrich response with stream metadata
	response.ClientIP = stream.ClientIP
	response.ServerIP = stream.ServerIP
	response.ClientPort = stream.ClientPort
	response.ServerPort = stream.ServerPort
	response.Timestamp = stream.EndTime

	p.parsedResponses++

	// Try to match with pending request or store for later matching
	p.matchResponse(response)
}

// Parse parses raw HTTP request data
func (rp *RequestParser) Parse(data []byte) (*HTTPRequest, error) {
	reader := bytes.NewReader(data)
	bufReader := bufio.NewReader(reader)

	// Parse first line (method, URL, protocol)
	firstLine, _, err := bufReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}

	parts := strings.SplitN(string(firstLine), " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid request line format: %s", string(firstLine))
	}

	method := parts[0]
	rawURL := parts[1]
	protocol := parts[2]

	// Parse URL and extract components
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	request := &HTTPRequest{
		Method:      method,
		URL:         rawURL,
		Path:        parsedURL.Path,
		Protocol:    protocol,
		Headers:     make(map[string]string),
		Cookies:     make(map[string]string),
		QueryParams: make(map[string]string),
		FormParams:  make(map[string]string),
		JSONParams:  make(map[string]interface{}),
	}

	// Extract query parameters
	for key, values := range parsedURL.Query() {
		if len(values) > 0 {
			request.QueryParams[key] = values[0] // Take first value
		}
	}

	// Parse headers
	err = rp.parseHeaders(bufReader, request)
	if err != nil {
		return nil, fmt.Errorf("failed to parse headers: %w", err)
	}

	// Parse body if present
	err = rp.parseBody(bufReader, request)
	if err != nil {
		return nil, fmt.Errorf("failed to parse body: %w", err)
	}

	return request, nil
}

// parseHeaders parses HTTP headers
func (rp *RequestParser) parseHeaders(reader *bufio.Reader, request *HTTPRequest) error {
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		lineStr := string(line)

		// Empty line indicates end of headers
		if lineStr == "" {
			break
		}

		// Parse header
		parts := strings.SplitN(lineStr, ":", 2)
		if len(parts) != 2 {
			continue // Skip malformed headers
		}

		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])

		request.Headers[headerName] = headerValue

		// Extract common headers
		switch strings.ToLower(headerName) {
		case "user-agent":
			request.UserAgent = headerValue
		case "referer":
			request.Referer = headerValue
		case "authorization":
			request.Authorization = headerValue
		case "content-type":
			request.ContentType = headerValue
		case "content-length":
			if length, err := strconv.ParseInt(headerValue, 10, 64); err == nil {
				request.ContentLength = length
			}
		case "cookie":
			rp.parseCookies(headerValue, request)
		}
	}

	return nil
}

// parseCookies parses cookie header
func (rp *RequestParser) parseCookies(cookieHeader string, request *HTTPRequest) {
	cookies := strings.Split(cookieHeader, ";")
	for _, cookie := range cookies {
		parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
		if len(parts) == 2 {
			request.Cookies[parts[0]] = parts[1]
		}
	}
}

// parseBody parses request body based on content type
func (rp *RequestParser) parseBody(reader *bufio.Reader, request *HTTPRequest) error {
	if request.ContentLength <= 0 {
		return nil // No body
	}

	// Limit body size
	bodySize := request.ContentLength
	if bodySize > int64(rp.maxBodySize) {
		bodySize = int64(rp.maxBodySize)
	}

	// Read body
	bodyBytes := make([]byte, bodySize)
	n, err := io.ReadFull(reader, bodyBytes)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}

	bodyBytes = bodyBytes[:n]
	request.Body = string(bodyBytes)

	// Parse body based on content type
	contentType := strings.ToLower(request.ContentType)

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		rp.parseFormBody(request.Body, request)
	} else if strings.Contains(contentType, "application/json") {
		rp.parseJSONBody(request.Body, request)
	} else if strings.Contains(contentType, "multipart/form-data") {
		// Multipart parsing would be more complex, skip for now
		// Could be added later if needed
	}

	return nil
}

// parseFormBody parses URL-encoded form data
func (rp *RequestParser) parseFormBody(body string, request *HTTPRequest) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return // Skip malformed form data
	}

	for key, vals := range values {
		if len(vals) > 0 {
			request.FormParams[key] = vals[0] // Take first value
		}
	}
}

// parseJSONBody parses JSON body
func (rp *RequestParser) parseJSONBody(body string, request *HTTPRequest) {
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
		request.JSONParams = jsonData
	}
	// If parsing fails, leave JSONParams empty
}

// Parse parses raw HTTP response data
func (rsp *ResponseParser) Parse(data []byte) (*HTTPResponse, error) {
	reader := bytes.NewReader(data)
	bufReader := bufio.NewReader(reader)

	// Parse status line
	statusLine, _, err := bufReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read status line: %w", err)
	}

	parts := strings.SplitN(string(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid status line format: %s", string(statusLine))
	}

	protocol := parts[0]
	statusCodeStr := parts[1]
	statusText := ""
	if len(parts) == 3 {
		statusText = parts[2]
	}

	statusCode, err := strconv.Atoi(statusCodeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %s", statusCodeStr)
	}

	response := &HTTPResponse{
		StatusCode: statusCode,
		StatusText: statusText,
		Protocol:   protocol,
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	// Parse headers
	err = rsp.parseHeaders(bufReader, response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse headers: %w", err)
	}

	// Parse body
	err = rsp.parseBody(bufReader, response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse body: %w", err)
	}

	return response, nil
}

// parseHeaders parses response headers
func (rsp *ResponseParser) parseHeaders(reader *bufio.Reader, response *HTTPResponse) error {
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		lineStr := string(line)

		// Empty line indicates end of headers
		if lineStr == "" {
			break
		}

		// Parse header
		parts := strings.SplitN(lineStr, ":", 2)
		if len(parts) != 2 {
			continue // Skip malformed headers
		}

		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])

		response.Headers[headerName] = headerValue

		// Extract common headers
		switch strings.ToLower(headerName) {
		case "content-type":
			response.ContentType = headerValue
		case "content-length":
			if length, err := strconv.ParseInt(headerValue, 10, 64); err == nil {
				response.ContentLength = length
			}
		case "server":
			response.ServerHeader = headerValue
		case "set-cookie":
			rsp.parseCookies(headerValue, response)
		}
	}

	return nil
}

// parseCookies parses Set-Cookie headers
func (rsp *ResponseParser) parseCookies(setCookieHeader string, response *HTTPResponse) {
	// Basic cookie parsing - could be enhanced for attributes
	parts := strings.SplitN(setCookieHeader, "=", 2)
	if len(parts) == 2 {
		cookieName := strings.TrimSpace(parts[0])
		cookieValue := strings.TrimSpace(parts[1])

		// Remove attributes (path, domain, etc.)
		if idx := strings.Index(cookieValue, ";"); idx != -1 {
			cookieValue = cookieValue[:idx]
		}

		response.Cookies[cookieName] = cookieValue
	}
}

// parseBody parses response body
func (rsp *ResponseParser) parseBody(reader *bufio.Reader, response *HTTPResponse) error {
	if response.ContentLength <= 0 {
		// Try to read remaining data anyway (chunked encoding, etc.)
		bodyBytes, err := io.ReadAll(reader)
		if err != nil && err != io.EOF {
			return err
		}
		response.Body = string(bodyBytes)
		response.ContentLength = int64(len(bodyBytes))
		return nil
	}

	// Limit body size
	bodySize := response.ContentLength
	if bodySize > int64(rsp.maxBodySize) {
		bodySize = int64(rsp.maxBodySize)
	}

	// Read body
	bodyBytes := make([]byte, bodySize)
	n, err := io.ReadFull(reader, bodyBytes)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}

	bodyBytes = bodyBytes[:n]
	response.Body = string(bodyBytes)

	return nil
}

// Conversation matching and management

// matchRequest tries to match request with pending response
func (p *Parser) matchRequest(request *HTTPRequest) {
	p.matchMutex.Lock()
	defer p.matchMutex.Unlock()

	// Create connection key for matching
	connKey := fmt.Sprintf("%s:%d->%s:%d",
		request.ClientIP.String(), request.ClientPort,
		request.ServerIP.String(), request.ServerPort)

	// Check if there's a pending response for this connection
	if response, exists := p.pendingResponses[connKey]; exists {
		// Match found - create conversation
		p.createConversation(request, response)
		delete(p.pendingResponses, connKey)
		p.matchedConvs++
	} else {
		// Store request for later matching
		p.pendingRequests[connKey] = request

		// Set timeout for cleanup
		go func() {
			time.Sleep(p.timeout)
			p.matchMutex.Lock()
			delete(p.pendingRequests, connKey)
			p.matchMutex.Unlock()
		}()
	}
}

// matchResponse tries to match response with pending request
func (p *Parser) matchResponse(response *HTTPResponse) {
	p.matchMutex.Lock()
	defer p.matchMutex.Unlock()

	// Create connection key for matching (reverse direction)
	connKey := fmt.Sprintf("%s:%d->%s:%d",
		response.ClientIP.String(), response.ClientPort,
		response.ServerIP.String(), response.ServerPort)

	// Check if there's a pending request for this connection
	if request, exists := p.pendingRequests[connKey]; exists {
		// Match found - create conversation
		p.createConversation(request, response)
		delete(p.pendingRequests, connKey)
		p.matchedConvs++
	} else {
		// Store response for later matching
		p.pendingResponses[connKey] = response

		// Set timeout for cleanup
		go func() {
			time.Sleep(p.timeout)
			p.matchMutex.Lock()
			delete(p.pendingResponses, connKey)
			p.matchMutex.Unlock()
		}()
	}
}

// createConversation creates a complete HTTP conversation
func (p *Parser) createConversation(request *HTTPRequest, response *HTTPResponse) {
	conversationID := fmt.Sprintf("%d_%s_%s",
		time.Now().UnixNano(),
		request.ClientIP.String(),
		request.Method)

	conversation := &HTTPConversation{
		ID:          conversationID,
		ClientIP:    request.ClientIP,
		ServerIP:    request.ServerIP,
		ClientPort:  request.ClientPort,
		ServerPort:  request.ServerPort,
		Protocol:    "http", // Will be updated for HTTPS
		StartTime:   request.Timestamp,
		EndTime:     response.Timestamp,
		Duration:    response.Timestamp.Sub(request.Timestamp),
		Request:     request,
		Response:    response,
		IsCompleted: true,
		HasErrors:   false,
		Errors:      []string{},
	}

	// Store conversation
	p.mu.Lock()
	p.conversations[conversationID] = conversation
	p.mu.Unlock()

	// Call callback if set
	if p.conversationCallback != nil {
		p.conversationCallback(conversation)
	}
}

// Helper methods

func (p *Parser) extractFirstLine(data []byte) (string, error) {
	reader := bytes.NewReader(data)
	bufReader := bufio.NewReader(reader)

	line, _, err := bufReader.ReadLine()
	if err != nil {
		return "", err
	}

	return string(line), nil
}

func (p *Parser) isHTTPRequest(firstLine string) bool {
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}

	for _, method := range httpMethods {
		if strings.HasPrefix(firstLine, method+" ") {
			return true
		}
	}

	return false
}

func (p *Parser) isHTTPResponse(firstLine string) bool {
	return strings.HasPrefix(firstLine, "HTTP/")
}

func (p *Parser) recordError(err error) {
	p.parseErrors++

	if p.errorCallback != nil {
		p.errorCallback(err)
	}
}

// Cleanup routine
func (p *Parser) cleanupRoutine() {
	for {
		select {
		case <-p.cleanupTicker.C:
			p.cleanupOldConversations()
		case <-p.stopCleanup:
			return
		}
	}
}

func (p *Parser) cleanupOldConversations() {
	cutoff := time.Now().Add(-p.retainDuration)

	p.mu.Lock()
	defer p.mu.Unlock()

	for id, conv := range p.conversations {
		if conv.EndTime.Before(cutoff) {
			delete(p.conversations, id)
		}
	}
}

// Public interface methods

// SetConversationCallback sets callback for completed conversations
func (p *Parser) SetConversationCallback(callback func(*HTTPConversation)) {
	p.conversationCallback = callback
}

// SetErrorCallback sets callback for parsing errors
func (p *Parser) SetErrorCallback(callback func(error)) {
	p.errorCallback = callback
}

// GetStats returns parsing statistics
func (p *Parser) GetStats() (requests, responses, conversations, errors int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.parsedRequests, p.parsedResponses, p.matchedConvs, p.parseErrors
}

// GetConversations returns all stored conversations
func (p *Parser) GetConversations() map[string]*HTTPConversation {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Return copy to prevent race conditions
	result := make(map[string]*HTTPConversation)
	for id, conv := range p.conversations {
		result[id] = conv
	}

	return result
}

// ParseHTTPStream parses an HTTP stream and reconstructs the conversation
func (p *Parser) ParseHTTPStream(stream *HTTPStream) (*HTTPConversation, error) {
	if stream == nil {
		return nil, fmt.Errorf("stream is nil")
	}

	fmt.Printf("DEBUG ParseHTTPStream: ID=%s, RawRequest=%d bytes, RawResponse=%d bytes\n",
		stream.ID, len(stream.RawRequest), len(stream.RawResponse))

	// Get or create conversation
	conversation := p.getOrCreateConversation(stream)

	// Add request if present
	if err := p.addRequestIfPresent(conversation, stream); err != nil {
		return nil, err
	}

	// Add response if present
	if err := p.addResponseIfPresent(conversation, stream); err != nil {
		return nil, err
	}

	// Finalize conversation
	p.finalizeConversation(conversation, stream)

	return conversation, nil
}

// getOrCreateConversation retrieves existing conversation or creates new one
func (p *Parser) getOrCreateConversation(stream *HTTPStream) *HTTPConversation {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existingConv, exists := p.conversations[stream.ID]; exists {
		fmt.Printf("DEBUG: Found existing conversation for ID=%s\n", stream.ID)
		return existingConv
	}

	conversation := &HTTPConversation{
		ID:          stream.ID,
		ClientIP:    stream.ClientIP,
		ServerIP:    stream.ServerIP,
		ClientPort:  stream.ClientPort,
		ServerPort:  stream.ServerPort,
		Protocol:    "http",
		StartTime:   stream.StartTime,
		EndTime:     stream.EndTime,
		Duration:    stream.EndTime.Sub(stream.StartTime),
		IsCompleted: false,
		HasErrors:   false,
		Errors:      []string{},
	}

	p.conversations[stream.ID] = conversation
	fmt.Printf("DEBUG: Created new conversation for ID=%s\n", stream.ID)
	return conversation
}

// addRequestIfPresent parses and adds request to conversation if present
func (p *Parser) addRequestIfPresent(conversation *HTTPConversation, stream *HTTPStream) error {
	if len(stream.RawRequest) == 0 || conversation.Request != nil {
		return nil // No request data or already has request
	}

	request, err := p.requestParser.Parse(stream.RawRequest)
	if err != nil {
		fmt.Printf("DEBUG: Failed to parse request: %v\n", err)
		return fmt.Errorf("failed to parse request: %w", err)
	}

	p.enrichRequestMetadata(request, stream)
	conversation.Request = request

	fmt.Printf("DEBUG: Added request to conversation: %s %s\n", request.Method, request.Path)
	return nil
}

// addResponseIfPresent parses and adds response to conversation if present
func (p *Parser) addResponseIfPresent(conversation *HTTPConversation, stream *HTTPStream) error {
	if len(stream.RawResponse) == 0 || conversation.Response != nil {
		return nil // No response data or already has response
	}

	response, err := p.responseParser.Parse(stream.RawResponse)
	if err != nil {
		fmt.Printf("DEBUG: Failed to parse response: %v\n", err)
		return fmt.Errorf("failed to parse response: %w", err)
	}

	p.enrichResponseMetadata(response, stream)
	conversation.Response = response

	fmt.Printf("DEBUG: Added response to conversation: %d %s\n", response.StatusCode, response.StatusText)
	return nil
}

// enrichRequestMetadata adds stream metadata to parsed request
func (p *Parser) enrichRequestMetadata(request *HTTPRequest, stream *HTTPStream) {
	request.ClientIP = stream.ClientIP
	request.ServerIP = stream.ServerIP
	request.ClientPort = stream.ClientPort
	request.ServerPort = stream.ServerPort
	request.Timestamp = stream.StartTime
}

// enrichResponseMetadata adds stream metadata to parsed response
func (p *Parser) enrichResponseMetadata(response *HTTPResponse, stream *HTTPStream) {
	response.ClientIP = stream.ClientIP
	response.ServerIP = stream.ServerIP
	response.ClientPort = stream.ClientPort
	response.ServerPort = stream.ServerPort
	response.Timestamp = stream.EndTime
}

// finalizeConversation updates conversation state and timing
func (p *Parser) finalizeConversation(conversation *HTTPConversation, stream *HTTPStream) {
	// Update completion status
	conversation.IsCompleted = conversation.Request != nil && conversation.Response != nil

	// Update timing
	if stream.StartTime.Before(conversation.StartTime) || conversation.StartTime.IsZero() {
		conversation.StartTime = stream.StartTime
	}
	if stream.EndTime.After(conversation.EndTime) {
		conversation.EndTime = stream.EndTime
	}
	conversation.Duration = conversation.EndTime.Sub(conversation.StartTime)

	// Store updated conversation
	p.mu.Lock()
	p.conversations[stream.ID] = conversation
	p.mu.Unlock()

	fmt.Printf("DEBUG: Updated conversation ID=%s, HasRequest=%t, HasResponse=%t, IsCompleted=%t\n",
		conversation.ID, conversation.Request != nil, conversation.Response != nil, conversation.IsCompleted)
}

// Close stops the parser and cleans up resources
func (p *Parser) Close() {
	if p.cleanupTicker != nil {
		p.cleanupTicker.Stop()
	}

	close(p.stopCleanup)
}
