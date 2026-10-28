//go:build linux

package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// Validate RSA against the real HY2 client with its default Chrome QUIC
// behavior. A successful x509 parser alone would not prove this compatibility.
func TestOfficialCoreCertificateRSAHY2TCPUDP(t *testing.T) {
	core := os.Getenv("SING_BOX_BIN")
	if core == "" {
		t.Skip("requires verified official sing-box")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(707), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	s := NewState()
	s.Certificates = []CertificateResource{{ID: Token(8), Name: "RSA2048 fixture", Certificate: Certificate{Mode: "pem", ServerName: "localhost", CertPEM: string(certPEM), KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}}}
	s.Nodes = []Node{{ID: Token(8), Name: "RSA HY2 entry", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		CertificateID: s.Certificates[0].ID, Users: []User{{ID: Token(8), Name: "original device", Password: "fixture-auth-preserved"}}}}
	b := &hy2ContinuityBackend{processBackend: processBackend{root: t.TempDir(), bin: core}}
	store := &Store{Root: b.root, Backend: b, GID: -1}
	t.Cleanup(func() {
		if err := b.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := store.WithLock(func() error { return store.Apply(s) }); err != nil {
		t.Fatal(err)
	}
	acmeFixtureHY2(t, core, s.Nodes[0].Port, "localhost", certPEM)
	t.Log("RSA2048 certificate served real HTTPS and two authenticated sequence UDP samples through HY2 with the client's default Chrome QUIC behavior")
}
