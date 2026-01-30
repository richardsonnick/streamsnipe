package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// generateSelfSignedCert creates a temporary self-signed certificate in memory
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Parse into tls.Certificate
	return tls.X509KeyPair(certPEM, keyPEM)
}

// startServer runs a TLS server that accepts one connection
func startServer(cert tls.Certificate, ready chan<- struct{}) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // Force TLS 1.2 like the Python version
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:8443", config)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Println("Server: Listening on 8443...")
	ready <- struct{}{} // Signal that server is ready

	// Accept one connection
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	state := tlsConn.ConnectionState()
	fmt.Printf("Server: Established TLS %x connection from %s\n",
		state.Version, conn.RemoteAddr())
	fmt.Printf("Server: Cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))

	_, err = conn.Write([]byte("Hello from the server!"))
	return err
}

// startClient connects to the TLS server
func startClient() error {
	config := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for self-signed cert
	}

	fmt.Println("Client: Connecting to server...")
	conn, err := tls.Dial("tcp", "127.0.0.1:8443", config)
	if err != nil {
		return err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Printf("Client: Handshake complete. TLS version: %x\n", state.Version)
	fmt.Printf("Client: Cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	fmt.Printf("Client: Received: %s\n", string(buf[:n]))
	return nil
}

func main() {
	// Generate self-signed certificate
	fmt.Println("Generating self-signed certificate...")
	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Printf("Failed to generate cert: %v\n", err)
		return
	}

	// Channel to signal when server is ready
	ready := make(chan struct{})
	serverErr := make(chan error, 1)

	// Start server in goroutine
	go func() {
		serverErr <- startServer(cert, ready)
	}()

	// Wait for server to be ready
	<-ready
	time.Sleep(100 * time.Millisecond) // Small buffer

	// Run client
	if err := startClient(); err != nil {
		fmt.Printf("Client error: %v\n", err)
	}

	// Check for server errors
	if err := <-serverErr; err != nil {
		fmt.Printf("Server error: %v\n", err)
	}

	fmt.Println("Done!")
}

