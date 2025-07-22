package jwt

func (jf *JWTFuzzer) incrementTestCount() {
	jf.mu.Lock()
	jf.testsExecuted++
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordSuccessfulTest() {
	jf.mu.Lock()
	jf.successfulTests++
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordFailedTest() {
	jf.mu.Lock()
	jf.failedTests++
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordVulnerability(vuln JWTVulnerability) {
	jf.mu.Lock()
	jf.vulnerabilities = append(jf.vulnerabilities, vuln)
	jf.mu.Unlock()
}

func (jf *JWTFuzzer) recordTokenAnalysis(analysis TokenAnalysis) {
	jf.mu.Lock()
	jf.tokensAnalyzed = append(jf.tokensAnalyzed, analysis)
	jf.mu.Unlock()
}
