package injection

// Thread-safe state management methods

// incrementTestCount increments the test counter safely
func (it *InjectionTester) incrementTestCount() {
	it.mu.Lock()
	it.testsExecuted++
	it.mu.Unlock()
}

// recordSuccessfulTest records a successful test
func (it *InjectionTester) recordSuccessfulTest() {
	it.mu.Lock()
	it.successfulTests++
	it.mu.Unlock()
}

// recordFailedTest records a failed test
func (it *InjectionTester) recordFailedTest() {
	it.mu.Lock()
	it.failedTests++
	it.mu.Unlock()
}

// recordVulnerability records a discovered vulnerability
func (it *InjectionTester) recordVulnerability(vuln InjectionVulnerability) {
	it.mu.Lock()
	it.vulnerabilities = append(it.vulnerabilities, vuln)
	it.mu.Unlock()
}

// recordParameterTest records a parameter test result
func (it *InjectionTester) recordParameterTest(test ParameterTest) {
	it.mu.Lock()
	it.testedParameters = append(it.testedParameters, test)
	it.mu.Unlock()
}
