package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertGenerator generates TLS certificates for MITM interception
type CertGenerator struct {
	// CA certificate and key
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caTLSCert tls.Certificate

	// Cache of generated certificates
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewCertGenerator creates a new certificate generator with its own CA
func NewCertGenerator() (*CertGenerator, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"CyberRaven Security Testing"},
			OrganizationalUnit: []string{"MITM Proxy CA"},
			CommonName:         "CyberRaven MITM CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Create TLS certificate from CA cert and key
	caTLSCert := tls.Certificate{
		Certificate: [][]byte{caCertDER},
		PrivateKey:  caKey,
		Leaf:        caCert,
	}

	return &CertGenerator{
		caCert:    caCert,
		caKey:     caKey,
		caTLSCert: caTLSCert,
		cache:     make(map[string]*tls.Certificate),
	}, nil
}

// GenerateForHost generates a certificate for a specific hostname
func (cg *CertGenerator) GenerateForHost(host string) (*tls.Certificate, error) {
	// Check cache first
	cg.mu.RLock()
	if cert, exists := cg.cache[host]; exists {
		cg.mu.RUnlock()
		return cert, nil
	}
	cg.mu.RUnlock()

	// Generate new certificate
	cert, err := cg.generateCert(host)
	if err != nil {
		return nil, err
	}

	// Cache it
	cg.mu.Lock()
	cg.cache[host] = cert
	cg.mu.Unlock()

	return cert, nil
}

// generateCert generates a new certificate for a host
func (cg *CertGenerator) generateCert(host string) (*tls.Certificate, error) {
	// Generate private key for the certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CyberRaven Security Testing"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour), // Short-lived for security
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add host to SANs
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
		// Also add wildcard for subdomains
		if host != "" && host[0] != '*' {
			template.DNSNames = append(template.DNSNames, "*."+host)
		}
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, cg.caCert, &privKey.PublicKey, cg.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, cg.caCert.Raw},
		PrivateKey:  privKey,
		Leaf:        cert,
	}

	return tlsCert, nil
}

// GetCACertPEM returns the CA certificate in PEM format
// This can be installed in browsers/systems to trust our MITM certs
func (cg *CertGenerator) GetCACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cg.caCert.Raw,
	})
}

// GetCAKeyPEM returns the CA private key in PEM format
// WARNING: This should be kept secure
func (cg *CertGenerator) GetCAKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cg.caKey),
	})
}

// ClearCache clears the certificate cache
func (cg *CertGenerator) ClearCache() {
	cg.mu.Lock()
	cg.cache = make(map[string]*tls.Certificate)
	cg.mu.Unlock()
}

// CacheSize returns the number of cached certificates
func (cg *CertGenerator) CacheSize() int {
	cg.mu.RLock()
	defer cg.mu.RUnlock()
	return len(cg.cache)
}
