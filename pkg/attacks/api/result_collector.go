package api

import "sync"

// ResultCollector handles thread-safe collection of test results
type ResultCollector struct {
	mu               sync.RWMutex
	testedCount      int
	foundEndpoints   []EndpointResult
	erroredEndpoints []EndpointError
	vulnerabilities  []VulnerabilityFinding
}

// NewResultCollector creates a new result collector
func NewResultCollector() *ResultCollector {
	return &ResultCollector{
		foundEndpoints:   make([]EndpointResult, 0),
		erroredEndpoints: make([]EndpointError, 0),
		vulnerabilities:  make([]VulnerabilityFinding, 0),
	}
}

// IncrementTestedCount increments the tested endpoint counter
func (rc *ResultCollector) IncrementTestedCount() {
	rc.mu.Lock()
	rc.testedCount++
	rc.mu.Unlock()
}

// RecordEndpoint records a discovered endpoint
func (rc *ResultCollector) RecordEndpoint(result EndpointResult) {
	rc.mu.Lock()
	rc.foundEndpoints = append(rc.foundEndpoints, result)
	rc.mu.Unlock()
}

// RecordError records an error encountered during testing
func (rc *ResultCollector) RecordError(path, method, errorType, errorMsg string) {
	rc.mu.Lock()
	rc.erroredEndpoints = append(rc.erroredEndpoints, EndpointError{
		Path:      path,
		Method:    method,
		Error:     errorMsg,
		ErrorType: errorType,
	})
	rc.mu.Unlock()
}

// RecordVulnerability records a discovered vulnerability
func (rc *ResultCollector) RecordVulnerability(vuln VulnerabilityFinding) {
	rc.mu.Lock()
	rc.vulnerabilities = append(rc.vulnerabilities, vuln)
	rc.mu.Unlock()
}

// GetResults returns the collected results in a thread-safe manner
func (rc *ResultCollector) GetResults() (int, []EndpointResult, []EndpointError, []VulnerabilityFinding) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	// Create copies to avoid race conditions
	foundEndpoints := make([]EndpointResult, len(rc.foundEndpoints))
	copy(foundEndpoints, rc.foundEndpoints)

	erroredEndpoints := make([]EndpointError, len(rc.erroredEndpoints))
	copy(erroredEndpoints, rc.erroredEndpoints)

	vulnerabilities := make([]VulnerabilityFinding, len(rc.vulnerabilities))
	copy(vulnerabilities, rc.vulnerabilities)

	return rc.testedCount, foundEndpoints, erroredEndpoints, vulnerabilities
}
