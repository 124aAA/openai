package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func makeCert(t *testing.T) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}
func startCore(t *testing.T, bin string, config []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if e := os.WriteFile(p, config, 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command(bin, "check", "-c", p).CombinedOutput(); e != nil {
		t.Fatalf("core rejected generated config: %v\n%s", e, out)
	}
	cmd := exec.Command(bin, "run", "-c", p)
	logfile, e := os.CreateTemp(t.TempDir(), "core-log-")
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stdout = logfile
	cmd.Stderr = logfile
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("core did not stop")
		}
		logfile.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logfile.Name())
			t.Logf("core log: %s", b)
		}
	})
	time.Sleep(250 * time.Millisecond)
}
func socksUDP(t *testing.T, port int) {
	t.Helper()
	echo, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		n, addr, e := echo.ReadFrom(b)
		if e == nil {
			_, _ = echo.WriteTo(b[:n], addr)
		}
	}()
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	c.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	if _, e = io.ReadFull(c, r); e != nil || r[1] != 0 {
		t.Fatal("SOCKS greeting", e)
	}
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	h := make([]byte, 4)
	if _, e = io.ReadFull(c, h); e != nil || h[1] != 0 {
		t.Fatal("SOCKS associate", e)
	}
	size := 4
	if h[3] == 4 {
		size = 16
	} else if h[3] != 1 {
		t.Fatal("unsupported reply address")
	}
	addr := make([]byte, size+2)
	if _, e = io.ReadFull(c, addr); e != nil {
		t.Fatal(e)
	}
	relayPort := int(binary.BigEndian.Uint16(addr[size:]))
	ip := net.IP(addr[:size])
	if ip.IsUnspecified() {
		ip = net.ParseIP("127.0.0.1")
	}
	u, e := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: relayPort})
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(8 * time.Second))
	payload := []byte("qingnode-udp-roundtrip")
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], uint16(echo.LocalAddr().(*net.UDPAddr).Port))
	packet = append(packet, payload...)
	if _, e = u.Write(packet); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 2048)
	n, e := u.Read(buf)
	if e != nil || !bytes.HasSuffix(buf[:n], payload) {
		t.Fatal("UDP echo failed", e)
	}
}
func TestOfficialCoreEndToEnd(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("set SING_BOX_BIN to a verified official 1.14.x binary")
	}
	cert, key := makeCert(t)
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("target")) }))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("qingnode-verified-payload")) }))
	defer origin.Close()
	s := NewState()
	r, e := NewReality("localhost", target.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	s.Nodes = []Node{{ID: Token(8), Name: "REALITY 测试", Protocol: "reality", Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true, Users: []User{NewUser("test", "reality")}, Reality: r}, {ID: Token(8), Name: "HY2 测试", Protocol: "hysteria2", Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true, Users: []User{NewUser("test", "hysteria2")}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}}}
	ss := ssFixture()
	ss.Listen = "127.0.0.1"
	ss.Host = "127.0.0.1"
	ss.Port = freePort(t)
	s.Nodes = append(s.Nodes, ss)
	server, e := Server(s, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, server)
	for _, n := range s.Nodes {
		t.Run(n.Protocol, func(t *testing.T) {
			port := freePort(t)
			config := Client(n, n.Users[0], port)
			// The test fixture has a private CA. Add that trust root only to the test client;
			// production exporters never disable verification or silently trust arbitrary certs.
			if n.Protocol == "hysteria2" {
				config["outbounds"].([]any)[0].(M)["tls"].(M)["certificate"] = []string{cert}
			}
			b, e := json.Marshal(config)
			if e != nil {
				t.Fatal(e)
			}
			startCore(t, bin, b)
			proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
			var resp *http.Response
			for i := 0; i < 8; i++ {
				resp, e = client.Get(origin.URL)
				if e == nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			if e != nil || string(body) != "qingnode-verified-payload" {
				t.Fatal("HTTP payload mismatch", e)
			}
			socksUDP(t, port)
		})
	}
}
func TestOfficialCoreACMESchema(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires official core")
	}
	s := NewState()
	s.Nodes = []Node{{ID: Token(8), Name: "ACME", Protocol: "hysteria2", Host: "example.com", Listen: "0.0.0.0", Port: 443, Enabled: true, Users: []User{NewUser("test", "hysteria2")}, Certificate: &Certificate{Mode: "acme", ServerName: "example.com", Email: "admin@example.com"}}}
	b, e := Server(s, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "acme.json")
	os.WriteFile(p, b, 0600)
	out, e := exec.Command(bin, "check", "-c", p).CombinedOutput()
	if e != nil {
		t.Fatalf("ACME 1.14 schema rejected: %v\n%s", e, out)
	}
}

func TestOfficialCoreAllExportedConfigs(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires official core")
	}
	cert, key := makeCert(t)
	s := fixture(t)
	s.Nodes = append(s.Nodes, Node{ID: Token(8), Name: "HY2 国际 # : %", Protocol: "hysteria2", Host: "2001:db8::1", Listen: "::", Port: 443, Enabled: true, Users: []User{NewUser("Android", "hysteria2")}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}})
	ss := ssFixture()
	ss.Listen = "127.0.0.1"
	ss.Host = "127.0.0.1"
	ss.Port = freePort(t)
	s.Nodes = append(s.Nodes, ss)
	server, e := Server(s, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	configs := [][]byte{server}
	for _, n := range s.Nodes {
		b, e := Export(n, n.Users[0], "sing-box")
		if e != nil {
			t.Fatal(e)
		}
		configs = append(configs, b)
	}
	for _, b := range configs {
		p := filepath.Join(t.TempDir(), "config.json")
		if e = os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		out, e := exec.Command(bin, "check", "-c", p).CombinedOutput()
		if e != nil {
			t.Fatalf("generated configuration rejected: %v\n%s", e, out)
		}
	}
}

func TestMihomoExportAcceptedByOfficialParser(t *testing.T) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Skip("set MIHOMO_BIN to a verified official binary")
	}
	cert, key := makeCert(t)
	s := fixture(t)
	s.Nodes = append(s.Nodes, Node{ID: Token(8), Name: "HY2 true : # %", Protocol: "hysteria2", Host: "2001:db8::2", Listen: "::", Port: 443, Enabled: true, Users: []User{NewUser("移动端", "hysteria2")}, Certificate: &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}})
	s.Nodes = append(s.Nodes, ssFixture())
	for _, n := range s.Nodes {
		b, e := Export(n, n.Users[0], "mihomo")
		if e != nil {
			t.Fatal(e)
		}
		dir := t.TempDir()
		p := filepath.Join(dir, "config.yaml")
		os.WriteFile(p, b, 0600)
		out, e := exec.Command(bin, "-t", "-d", dir, "-f", p).CombinedOutput()
		if e != nil {
			t.Fatalf("Mihomo rejected %s export: %v\n%s", n.Protocol, e, out)
		}
	}
}

func TestOfficialArchiveIntegrityAndInstallIdempotency(t *testing.T) {
	archive := os.Getenv("SING_BOX_ARCHIVE")
	if archive == "" {
		t.Skip("requires verified official archive")
	}
	st, _ := newStore(t)
	if e := st.WithLock(func() error { return InstallCore(st.Root, DefaultCore, "", archive) }); e != nil {
		t.Fatal(e)
	}
	if e := VerifyCore(st.Root, DefaultCore); e != nil {
		t.Fatal(e)
	}
	p := CorePath(st.Root, DefaultCore)
	before, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = st.WithLock(func() error { return InstallCore(st.Root, DefaultCore, "", "") }); e != nil {
		t.Fatal(e)
	}
	after, _ := os.Stat(p)
	if !os.SameFile(before, after) {
		t.Fatal("repeat download replaced an intact core")
	}
	if e = st.WithLock(func() error {
		return InstallCore(st.Root, DefaultCore, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", archive)
	}); e == nil {
		t.Fatal("wrong archive hash accepted")
	}
	if e = VerifyCore(st.Root, DefaultCore); e != nil {
		t.Fatal("failed install damaged existing core")
	}
}
