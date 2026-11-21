package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func makeCertForHost(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}

func compactJSONBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact JSON failed: %v\n%s", err, raw)
	}
	return buf.Bytes()
}

func TestRound3HY2SalamanderAndPortHopping(t *testing.T) {
	cert, key := makeCertForHost(t, "hy2.example.com")
	baseHY2 := func() Node {
		u := NewUser("alice", "hysteria2")
		u.Password = "user-auth-secret-1234"
		return Node{
			ID:          "1111111111111111",
			Name:        "HY2-Hop",
			Protocol:    "hysteria2",
			Host:        "hy2.example.com",
			Listen:      "0.0.0.0",
			Port:        8443,
			Enabled:     true,
			Users:       []User{u},
			Certificate: &Certificate{Mode: "pem", ServerName: "hy2.example.com", CertPEM: cert, KeyPEM: key},
		}
	}

	// 1. Salamander obfs + Port hopping client/server exports & redaction.
	n := baseHY2()
	n.HY2 = &HY2Performance{
		Obfs:        &HY2Obfs{Type: "salamander", Password: "obfs-secret-password!@#"},
		HopPorts:    "20000-30000",
		HopInterval: "30s",
		HopMode:     "external",
	}
	st := NewState()
	st.Nodes = []Node{n}
	if err := st.Validate(); err != nil {
		t.Fatalf("valid HY2 obfs + port-hopping rejected: %v", err)
	}

	redacted := Redact("obfs=obfs-secret-password!@# user=user-auth-secret-1234", st)
	if strings.Contains(redacted, "obfs-secret-password!@#") || strings.Contains(redacted, "user-auth-secret-1234") {
		t.Fatalf("HY2 obfs or user secret leaked through Redact: %q", redacted)
	}

	srvRaw, err := Server(st, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srvRaw = compactJSONBytes(t, srvRaw)
	if !bytes.Contains(srvRaw, []byte(`"obfs":{"password":"obfs-secret-password!@#","type":"salamander"}`)) {
		t.Fatalf("server inbound missing HY2 salamander obfs: %s", srvRaw)
	}

	out := Outbound(n, n.Users[0])
	outJSON, _ := json.Marshal(out)
	if !bytes.Contains(outJSON, []byte(`"server_ports":["20000:30000"]`)) || !bytes.Contains(outJSON, []byte(`"hop_interval":"30s"`)) || !bytes.Contains(outJSON, []byte(`"salamander"`)) {
		t.Fatalf("sing-box outbound missing HY2 hopping or obfs: %s", outJSON)
	}
	if _, hasSinglePort := out["server_port"]; hasSinglePort {
		t.Fatalf("sing-box outbound with server_ports should omit conflicting server_port: %v", out)
	}

	mihomoRaw, err := Export(n, n.Users[0], "mihomo")
	if err != nil {
		t.Fatal(err)
	}
	var mihomoDoc map[string]any
	if err = yaml.Unmarshal(mihomoRaw, &mihomoDoc); err != nil {
		t.Fatal(err)
	}
	px := mihomoDoc["proxies"].([]any)[0].(map[string]any)
	if px["obfs"] != "salamander" || px["obfs-password"] != "obfs-secret-password!@#" || px["ports"] != "20000-30000" || px["hop-interval"] != 30 {
		t.Fatalf("unexpected mihomo HY2 proxy fields: %#v", px)
	}

	// URI has lossy warning when hop_interval is set (rejected by Export unless allowLossy), and lossless when hop_interval is empty.
	if warnings := HY2ExportWarnings(n, "uri"); len(warnings) == 0 {
		t.Fatal("expected lossy warning on HY2 URI when hop_interval is configured")
	}
	if _, err := Export(n, n.Users[0], "uri"); err == nil {
		t.Fatal("Export(uri) should reject lossy HY2 hop_interval without allowLossy")
	}
	nNoInterval := n
	hy2Copy := *n.HY2
	hy2Copy.HopInterval = ""
	nNoInterval.HY2 = &hy2Copy
	if warnings := HY2ExportWarnings(nNoInterval, "uri"); len(warnings) != 0 {
		t.Fatalf("unexpected lossy warning on HY2 URI without hop_interval: %v", warnings)
	}
	uriStr, err := Export(nNoInterval, n.Users[0], "uri")
	if err != nil {
		t.Fatal(err)
	}
	parsedURI, err := url.Parse(strings.TrimSpace(string(uriStr)))
	if err != nil {
		t.Fatal(err)
	}
	q := parsedURI.Query()
	if q.Get("obfs") != "salamander" || q.Get("obfs-password") != "obfs-secret-password!@#" || q.Get("mport") != "20000-30000" {
		t.Fatalf("unexpected hysteria2 URI query: %s", parsedURI.RawQuery)
	}

	// 2. Negative validation: obfs reusing user password, bad hop ranges, and UDP port overlap.
	badSamePw := baseHY2()
	badSamePw.HY2 = &HY2Performance{Obfs: &HY2Obfs{Type: "salamander", Password: "user-auth-secret-1234"}}
	stBad := NewState()
	stBad.Nodes = []Node{badSamePw}
	if err := stBad.Validate(); err == nil {
		t.Fatal("accepted HY2 salamander obfs reusing user password")
	}

	for _, badHop := range []HY2Performance{
		{HopPorts: "80-1000"},
		{HopPorts: "30000-20000"},
		{HopPorts: "20000-20000"},
		{HopPorts: "10000-40000"}, // span > 20001
		{HopInterval: "30s"},      // interval without hop_ports
		{HopPorts: "20000-21000", HopInterval: "3s"},
		{HopPorts: "20000-21000", HopMode: "iptables"},
		{Obfs: &HY2Obfs{Type: "xor", Password: "valid-obfs-password"}},
	} {
		cand := baseHY2()
		hp := badHop
		cand.HY2 = &hp
		s := NewState()
		s.Nodes = []Node{cand}
		if err := s.Validate(); err == nil {
			t.Fatalf("accepted invalid HY2 hopping/obfs config: %+v", badHop)
		}
	}

	// Overlap with own listen port or another UDP forward/node must be rejected.
	selfOverlap := baseHY2()
	selfOverlap.Port = 25000
	selfOverlap.HY2 = &HY2Performance{HopPorts: "20000-30000"}
	sOverlap := NewState()
	sOverlap.Nodes = []Node{selfOverlap}
	if err := sOverlap.Validate(); err == nil {
		t.Fatal("accepted HY2 hop_ports overlapping own UDP listen port")
	}

	fwdOverlap := NewState()
	nHop := baseHY2()
	nHop.HY2 = &HY2Performance{HopPorts: "20000-30000", HopMode: "nftables"}
	fwdOverlap.Nodes = []Node{nHop}
	fwdOverlap.Forwards = []PortForward{{
		ID: "2222222222222222", Name: "udp-fwd", Listen: "0.0.0.0", Port: 25000,
		Network: "udp", TargetHost: "198.51.100.20", TargetPort: 53, Enabled: true,
	}}
	if err := fwdOverlap.Validate(); err == nil {
		t.Fatal("accepted HY2 hop_ports overlapping local UDP PortForward")
	}

	// 3. RenderHY2NftScript IPv4 / IPv6 dual-stack ownership & scoping.
	script := RenderHY2NftScript([]HY2RedirectRule{
		{NodeID: "n4wild", Listen: "0.0.0.0", ListenPort: 8443, PortStart: 20000, PortEnd: 20100},
		{NodeID: "n6wild", Listen: "::", ListenPort: 9443, PortStart: 21000, PortEnd: 21100},
		{NodeID: "n4ip", Listen: "198.51.100.9", ListenPort: 7443, PortStart: 22000, PortEnd: 22100},
		{NodeID: "n6ip", Listen: "2001:db8::9", ListenPort: 6443, PortStart: 23000, PortEnd: 23100},
	})
	for _, want := range []string{
		"add table inet qingnode_hy2; flush table inet qingnode_hy2;",
		`meta nfproto ipv4 udp dport 20000-20100 redirect to :8443 comment "qingnode:hy2:n4wild";`,
		`add rule inet qingnode_hy2 prerouting udp dport 21000-21100 redirect to :9443 comment "qingnode:hy2:n6wild";`,
		`ip daddr 198.51.100.9 udp dport 22000-22100 redirect to :7443 comment "qingnode:hy2:n4ip";`,
		`ip6 daddr 2001:db8::9 udp dport 23000-23100 redirect to :6443 comment "qingnode:hy2:n6ip";`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nftables script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatalf("nftables script must NEVER flush global ruleset: %s", script)
	}
	sFwD := NewState()
	sFwD.Firewall = "firewalld"
	nFwD := baseHY2()
	nFwD.Listen = "::"
	nFwD.HY2 = &HY2Performance{HopPorts: "21000-21100", HopMode: "nftables"}
	sFwD.Nodes = []Node{nFwD}
	fwRules := strings.Join(firewalldWanted(sFwD), "\n")
	if !strings.Contains(fwRules, `rule family="ipv4" port port="21000-21100" protocol="udp" accept`) ||
		!strings.Contains(fwRules, `rule family="ipv6" port port="21000-21100" protocol="udp" accept`) {
		t.Fatalf("firewalldWanted missing dual-stack HY2 UDP port range:\n%s", fwRules)
	}
	sFwD.Nodes[0].HY2.HopMode = "external"
	if strings.Contains(strings.Join(firewalldWanted(sFwD), "\n"), "21000-21100") {
		t.Fatal("firewalldWanted should not open HY2 hop range when hop_mode=external")
	}

	// 4. Transactional Apply -> failed candidate auto-Recover -> Rollback -> Uninstall cleanup.
	var nftTableExists bool
	var nftAppliedScripts []string
	var nftDeletedCount int
	ufw := newUFWFixture()
	ufw.lines = append(ufw.lines, "22/tcp ALLOW IN Anywhere # ssh-keep")
	execMock := func(_ time.Duration, name string, args ...string) ([]byte, error) {
		switch name {
		case "ufw":
			return ufw.run(args...)
		case "nft":
			if len(args) >= 4 && args[0] == "list" && args[1] == "table" && args[2] == "inet" && args[3] == HY2NftTable {
				if !nftTableExists {
					return []byte("Error: No such file or directory"), errors.New("exit status 1")
				}
				return []byte("table inet qingnode_hy2 {}"), nil
			}
			if len(args) >= 4 && args[0] == "delete" && args[1] == "table" && args[2] == "inet" && args[3] == HY2NftTable {
				nftTableExists = false
				nftDeletedCount++
				return nil, nil
			}
			if len(args) == 1 && strings.Contains(args[0], "table inet qingnode_hy2") {
				nftTableExists = true
				nftAppliedScripts = append(nftAppliedScripts, args[0])
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected nft call: %v", args)
		default:
			return nil, nil
		}
	}
	failNextActivate := false
	store := &Store{
		Root: filepath.Join(t.TempDir(), "store"),
		GID:  -1,
		Backend: &mockEffectsBackend{
			exec: execMock,
			activateFn: func(State) error {
				if failNextActivate {
					failNextActivate = false
					return errors.New("simulated core activation failure")
				}
				return nil
			},
		},
	}

	// Step A: Apply external mode -> no nft table created, UFW only opens 8443/udp.
	sExternal := NewState()
	sExternal.Firewall = "ufw"
	nExt := baseHY2()
	nExt.HY2 = &HY2Performance{HopPorts: "20000-20500", HopMode: "external"}
	sExternal.Nodes = []Node{nExt}
	if err := store.WithLock(func() error { return store.Apply(sExternal) }); err != nil {
		t.Fatalf("Apply external hop_mode failed: %v", err)
	}
	if nftTableExists || len(nftAppliedScripts) != 0 {
		t.Fatal("external hop_mode should not touch host nftables")
	}
	if strings.Contains(strings.Join(ufw.lines, "\n"), "20000:20500") {
		t.Fatalf("external hop_mode should not open local UFW hop range: %v", ufw.lines)
	}

	// Step B: Candidate switching to hop_mode="nftables" fails activation -> Recover cleans up nft table & UFW hop range while keeping ssh-keep and 8443/udp!
	sNft := sExternal.Clone()
	sNft.Nodes[0].HY2.HopMode = "nftables"
	sNft.Nodes[0].Port = 8444 // force runtime change so Activate runs
	failNextActivate = true
	if err := store.WithLock(func() error { return store.Apply(sNft) }); err == nil || !strings.Contains(err.Error(), "已恢复原状态") {
		t.Fatalf("expected simulated activation failure with automatic recovery, got: %v", err)
	}
	if nftTableExists || nftDeletedCount == 0 {
		t.Fatalf("failed candidate apply did not clean up table inet qingnode_hy2 (exists=%v deleted=%d)", nftTableExists, nftDeletedCount)
	}
	joinedUFW := strings.Join(ufw.lines, "\n")
	if strings.Contains(joinedUFW, "20000:20500") || !strings.Contains(joinedUFW, "ssh-keep") || !strings.Contains(joinedUFW, "8443/udp") {
		t.Fatalf("unexpected UFW rules after failed candidate recovery:\n%s", joinedUFW)
	}

	// Step C: Apply hop_mode="nftables" succeeds -> nft table active & UFW has 20000:20500/udp.
	if err := store.WithLock(func() error { return store.Apply(sNft) }); err != nil {
		t.Fatalf("Apply nftables hop_mode failed: %v", err)
	}
	if !nftTableExists || !strings.Contains(strings.Join(ufw.lines, "\n"), "20000:20500/udp") {
		t.Fatalf("expected active nft table and UFW port range, got nft=%v ufw=%v", nftTableExists, ufw.lines)
	}

	// Step D: Rollback to sExternal -> nft table deleted & UFW 20000:20500/udp pruned.
	if err := store.WithLock(func() error { return store.Rollback() }); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if nftTableExists || strings.Contains(strings.Join(ufw.lines, "\n"), "20000:20500/udp") {
		t.Fatalf("Rollback did not clean up nft table or UFW range: nft=%v ufw=%v", nftTableExists, ufw.lines)
	}

	// Step E: Re-apply sNft and verify FinishEffects(sNft, NewState()) (uninstall) cleans up nft + QingNode UFW rules while preserving ssh-keep.
	if err := store.WithLock(func() error { return store.Apply(sNft) }); err != nil {
		t.Fatal(err)
	}
	if err := (SystemBackend{Execute: execMock}).FinishEffects(sNft, NewState()); err != nil {
		t.Fatalf("uninstall FinishEffects failed: %v", err)
	}
	if nftTableExists || len(ufw.lines) != 1 || !strings.Contains(ufw.lines[0], "ssh-keep") {
		t.Fatalf("uninstall cleanup did not preserve foreign rule or leaked QingNode rules: nft=%v ufw=%v", nftTableExists, ufw.lines)
	}
}

type mockEffectsBackend struct {
	exec       Runner
	active     bool
	activateFn func(State) error
}

func (m *mockEffectsBackend) Check(State, string) error { return nil }
func (m *mockEffectsBackend) Active() bool              { return m.active }
func (m *mockEffectsBackend) Activate(s State) error {
	if m.activateFn != nil {
		if err := m.activateFn(s); err != nil {
			return err
		}
	}
	m.active = true
	return nil
}
func (m *mockEffectsBackend) Stop() error { m.active = false; return nil }
func (m *mockEffectsBackend) PrepareEffects(old, next State) error {
	return (SystemBackend{Execute: m.exec}).PrepareEffects(old, next)
}
func (m *mockEffectsBackend) FinishEffects(old, next State) error {
	return (SystemBackend{Execute: m.exec}).FinishEffects(old, next)
}

type ufwSimFixture struct {
	lines []string
}

func newUFWFixture() *ufwSimFixture { return &ufwSimFixture{} }

func (u *ufwSimFixture) run(args ...string) ([]byte, error) {
	if len(args) == 2 && args[0] == "status" && args[1] == "numbered" {
		var b strings.Builder
		b.WriteString("Status: active\n\n")
		for i, l := range u.lines {
			fmt.Fprintf(&b, "[ %d] %s\n", i+1, l)
		}
		return []byte(b.String()), nil
	}
	if len(args) >= 8 && args[0] == "allow" && args[1] == "in" && args[2] == "proto" {
		proto, portSpec, comment := args[3], "", ""
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "port":
				portSpec = args[i+1]
			case "comment":
				comment = args[i+1]
			}
		}
		line := fmt.Sprintf("%s/%s ALLOW IN Anywhere # %s", portSpec, proto, comment)
		for _, existing := range u.lines {
			if existing == line {
				return nil, nil
			}
		}
		u.lines = append(u.lines, line)
		return nil, nil
	}
	if len(args) == 3 && args[0] == "--force" && args[1] == "delete" {
		idx, err := strconv.Atoi(args[2])
		if err != nil || idx < 1 || idx > len(u.lines) {
			return nil, errors.New("invalid ufw rule index")
		}
		u.lines = append(u.lines[:idx-1], u.lines[idx:]...)
		return nil, nil
	}
	return nil, nil
}

func TestRound3TransportsEarlyDataHTTP2AndMultiplex(t *testing.T) {
	cert, key := makeCertForHost(t, "cdn.example.com")
	tlsCert := &Certificate{Mode: "pem", ServerName: "cdn.example.com", CertPEM: cert, KeyPEM: key}

	// 1. WS Early Data (default header & custom header) + VMess v2rayN ?ed=2048.
	vmessWS := Node{
		ID: "3333333333333333", Name: "VMess-WS-ED", Protocol: "vmess-tls",
		Host: "cdn.example.com", Listen: "0.0.0.0", Port: 443, Enabled: true,
		Transport:   &TransportOptions{Type: "ws", Path: "/ws", Host: "cdn.example.com", MaxEarlyData: 2048},
		Certificate: tlsCert,
		Users:       []User{NewUser("u1", "vmess-tls")},
	}
	s := NewState()
	s.Nodes = []Node{vmessWS}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid VMess WS EarlyData rejected: %v", err)
	}
	srv, err := Server(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv = compactJSONBytes(t, srv)
	if !bytes.Contains(srv, []byte(`"max_early_data":2048`)) || !bytes.Contains(srv, []byte(`"early_data_header_name":"Sec-WebSocket-Protocol"`)) {
		t.Fatalf("server WS early data missing: %s", srv)
	}
	uriRaw, err := Export(vmessWS, vmessWS.Users[0], "uri")
	if err != nil || !bytes.Contains(uriRaw, []byte("ed=2048")) {
		t.Fatalf("URI missing ed=2048: %v %s", err, uriRaw)
	}
	v2rayNRaw, err := Export(vmessWS, vmessWS.Users[0], "vmess-v2rayn")
	if err != nil {
		t.Fatal(err)
	}
	v2Decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(v2rayNRaw)), "vmess://"))
	if err != nil || !bytes.Contains(v2Decoded, []byte(`"/ws?ed=2048"`)) {
		t.Fatalf("vmess-v2rayn missing /ws?ed=2048: %v %s", err, v2Decoded)
	}
	// Custom header triggers lossy warning on vmess-v2rayn, while URI encodes &eh=...
	vmessCustomHdr := vmessWS
	trCopy := *vmessWS.Transport
	trCopy.EarlyDataHeaderName = "X-Early-Data"
	vmessCustomHdr.Transport = &trCopy
	if len(ProtocolExportWarnings(vmessCustomHdr, "vmess-v2rayn")) == 0 {
		t.Fatal("expected lossy warning for custom early_data_header_name on vmess-v2rayn")
	}
	customURI, err := Export(vmessCustomHdr, vmessCustomHdr.Users[0], "uri")
	if err != nil || !bytes.Contains(customURI, []byte("eh=X-Early-Data")) {
		t.Fatalf("URI missing eh=X-Early-Data: %v %s", err, customURI)
	}

	// 2. HTTP/2 (type: "http") transport on vless-tls, vmess-tls, trojan.
	for _, proto := range []string{"vless-tls", "vmess-tls", "trojan"} {
		h2Node := Node{
			ID: Token(8), Name: proto + "-h2", Protocol: proto,
			Host: "cdn.example.com", Listen: "0.0.0.0", Port: 443, Enabled: true,
			Transport:   &TransportOptions{Type: "http", Path: "/h2path", Host: "cdn.example.com"},
			Certificate: tlsCert,
			Users:       []User{NewUser("u1", proto)},
		}
		stH2 := NewState()
		stH2.Nodes = []Node{h2Node}
		if err := stH2.Validate(); err != nil {
			t.Fatalf("%s HTTP/2 rejected: %v", proto, err)
		}
		outJSON, _ := json.Marshal(Outbound(h2Node, h2Node.Users[0]))
		if !bytes.Contains(outJSON, []byte(`"type":"http"`)) || !bytes.Contains(outJSON, []byte(`"host":["cdn.example.com"]`)) || !bytes.Contains(outJSON, []byte(`"alpn":["h2"]`)) {
			t.Fatalf("%s HTTP/2 sing-box outbound mismatch: %s", proto, outJSON)
		}
		mhRaw, err := Export(h2Node, h2Node.Users[0], "mihomo")
		if err != nil || !bytes.Contains(mhRaw, []byte("network: h2")) || !bytes.Contains(mhRaw, []byte("h2-opts:")) {
			t.Fatalf("%s HTTP/2 mihomo mismatch: %v\n%s", proto, err, mhRaw)
		}
		uRaw, err := Export(h2Node, h2Node.Users[0], "uri")
		if err != nil || !bytes.Contains(uRaw, []byte("type=http")) {
			t.Fatalf("%s HTTP/2 URI mismatch: %v %s", proto, err, uRaw)
		}
	}

	// 3. TCP Multiplex across compatible protocols & mutual exclusion with Vision/QUIC/AnyTLS.
	for _, proto := range []string{"ss2022", "ss-aead", "trojan", "vmess-tls", "vless-tls"} {
		muxNode := Node{
			ID: Token(8), Name: proto + "-mux", Protocol: proto,
			Host: "cdn.example.com", Listen: "0.0.0.0", Port: 8443, Enabled: true,
			Multiplex: &MultiplexOptions{Enabled: true, Protocol: "yamux", MaxConnections: 4, MinStreams: 8, Padding: true},
		}
		switch proto {
		case "ss2022":
			muxNode.Shadowsocks = NewShadowsocks()
		case "ss-aead":
			muxNode.Shadowsocks, _ = NewShadowsocksAEAD(DefaultSSAEADMethod)
		default:
			muxNode.Certificate = tlsCert
		}
		muxNode.Users = []User{NewUserForNode("u1", muxNode)}
		stMux := NewState()
		stMux.Nodes = []Node{muxNode}
		if err := stMux.Validate(); err != nil {
			t.Fatalf("%s multiplex rejected: %v", proto, err)
		}
		srvMux, err := Server(stMux, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		srvMux = compactJSONBytes(t, srvMux)
		if !bytes.Contains(srvMux, []byte(`"multiplex":{"enabled":true,"padding":true}`)) {
			t.Fatalf("%s server multiplex mismatch: %s", proto, srvMux)
		}
		outMux, _ := json.Marshal(Outbound(muxNode, muxNode.Users[0]))
		if !bytes.Contains(outMux, []byte(`"protocol":"yamux"`)) || !bytes.Contains(outMux, []byte(`"max_connections":4`)) || !bytes.Contains(outMux, []byte(`"min_streams":8`)) {
			t.Fatalf("%s client multiplex mismatch: %s", proto, outMux)
		}
		mhMux, err := Export(muxNode, muxNode.Users[0], "mihomo")
		if err != nil || !bytes.Contains(mhMux, []byte("smux:")) || !bytes.Contains(mhMux, []byte("protocol: yamux")) {
			t.Fatalf("%s mihomo smux mismatch: %v\n%s", proto, err, mhMux)
		}
		if len(ProtocolExportWarnings(muxNode, "uri")) == 0 {
			t.Fatalf("%s with multiplex should warn/reject lossy URI export", proto)
		}
	}

	for _, incompatible := range []string{"reality", "hysteria2", "tuic", "anytls"} {
		if ProtocolSupportsMultiplex(incompatible) {
			t.Fatalf("%s must not claim multiplex support", incompatible)
		}
	}
}

func TestRound3RemoteEgressParityAndSS2022MultiCipher(t *testing.T) {
	// 1. SS2022 inbound multi-cipher (16B vs 32B strict Base64 keys).
	for _, method := range []string{SS2022Method, SS2022AES128Method, SS2022ChaCha20Method} {
		ss, err := NewShadowsocks2022(method)
		if err != nil {
			t.Fatalf("NewShadowsocks2022(%s): %v", method, err)
		}
		n := Node{
			ID: Token(8), Name: "ss-" + method, Protocol: "ss2022",
			Host: "198.51.100.10", Listen: "0.0.0.0", Port: 8388, Enabled: true,
			Shadowsocks: ss,
		}
		n.Users = []User{NewUserForNode("u1", n)}
		st := NewState()
		st.Nodes = []Node{n}
		if err := st.Validate(); err != nil {
			t.Fatalf("valid SS2022 %s rejected: %v", method, err)
		}
		// Mismatched user key length must fail validation.
		wrongLen := 16
		if method == SS2022AES128Method {
			wrongLen = 32
		}
		n.Users[0].Password = ssKeyBytes(wrongLen)
		st.Nodes[0] = n
		if err := st.Validate(); err == nil {
			t.Fatalf("SS2022 %s accepted user key of wrong byte length %d", method, wrongLen)
		}
	}

	// 2. Remote Egress parity across all newly added egress protocols + Redact coverage.
	cert, _ := makeCert(t)
	rSample, err := NewReality("www.microsoft.com", "www.microsoft.com:443")
	if err != nil {
		t.Fatal(err)
	}
	uuidSample := NewUser("u", "vless-tls").UUID
	aes128Key := ssKeyBytes(16) + ":" + ssKeyBytes(16)
	minIdle := 2

	st := NewState()
	st.Egresses = []Egress{
		{ID: "e000000000000001", Name: "http-plain", Protocol: "http", Server: "198.51.100.21", Port: 8080, UDP: false,
			HTTP: &RemoteHTTP{Username: "httpuser", Password: "http-secret-password-01"}},
		{ID: "e000000000000002", Name: "https-tls", Protocol: "http", Server: "198.51.100.22", Port: 8443, UDP: false,
			HTTP: &RemoteHTTP{Username: "httpsuser", Password: "https-secret-password-02", TLS: true, ServerName: "proxy.example.com", CertificatePEM: cert}},
		{ID: "e000000000000003", Name: "ss2022-128", Protocol: "ss2022", Server: "198.51.100.23", Port: 8388, UDP: true,
			Multiplex:   &MultiplexOptions{Enabled: true, Protocol: "h2mux", MaxConnections: 2},
			Shadowsocks: &RemoteSS{Method: SS2022AES128Method, Password: aes128Key}},
		{ID: "e000000000000004", Name: "ss-aead-out", Protocol: "ss-aead", Server: "198.51.100.24", Port: 8389, UDP: true,
			Shadowsocks: &RemoteSS{Method: "chacha20-ietf-poly1305", Password: "ssaead-secret-password-04"}},
		{ID: "e000000000000005", Name: "trojan-ws-mux", Protocol: "trojan", Server: "198.51.100.25", Port: 443, UDP: true,
			Transport: &TransportOptions{Type: "ws", Path: "/tr", MaxEarlyData: 2048},
			Multiplex: &MultiplexOptions{Enabled: true, Protocol: "smux", Padding: true},
			Trojan:    &RemoteTrojan{Password: "trojan-secret-password-05", ServerName: "tr.example.com", CertificatePEM: cert}},
		{ID: "e000000000000006", Name: "vless-h2-out", Protocol: "vless-tls", Server: "198.51.100.26", Port: 443, UDP: true,
			Transport: &TransportOptions{Type: "http", Path: "/vless-h2", Host: "vl.example.com"},
			VLESS:     &RemoteVLESS{UUID: uuidSample, ServerName: "vl.example.com", PacketEncoding: "xudp", CertificatePEM: cert}},
		{ID: "e000000000000007", Name: "vmess-hu-out", Protocol: "vmess-tls", Server: "198.51.100.27", Port: 443, UDP: true,
			Transport: &TransportOptions{Type: "httpupgrade", Path: "/vmess-up", Host: "vm.example.com"},
			VMess:     &RemoteVMess{UUID: uuidSample, Security: "aes-128-gcm", ServerName: "vm.example.com", PacketEncoding: "packetaddr", CertificatePEM: cert}},
		{ID: "e000000000000008", Name: "anytls-out", Protocol: "anytls", Server: "198.51.100.28", Port: 443, UDP: true,
			AnyTLS: &RemoteAnyTLS{Password: "anytls-secret-password-08", ServerName: "at.example.com", IdleSessionCheckInterval: "30s", IdleSessionTimeout: "60s", MinIdleSession: &minIdle, CertificatePEM: cert}},
		{ID: "e000000000000009", Name: "tuic-out", Protocol: "tuic", Server: "198.51.100.29", Port: 8443, UDP: true,
			TUIC: &RemoteTUIC{UUID: uuidSample, Password: "tuic-secret-password-09", ServerName: "tuic.example.com", CongestionControl: "bbr", UDPRelayMode: "native", Heartbeat: "10s", CertificatePEM: cert}},
		{ID: "e00000000000000a", Name: "reality-grpc-out", Protocol: "reality", Server: "198.51.100.30", Port: 443, UDP: true,
			Transport: &TransportOptions{Type: "grpc", ServiceName: "reality_grpc"},
			Reality:   &RemoteReality{UUID: uuidSample, ServerName: "www.microsoft.com", PublicKey: rSample.PublicKey, ShortID: "01020304", Fingerprint: "qq"}},
		{ID: "e00000000000000b", Name: "hy2-hop-out", Protocol: "hysteria2", Server: "198.51.100.31", Port: 8443, UDP: true,
			HY2: &RemoteHY2{Password: "hy2-remote-secret-11", ServerName: "hy2.example.com", CertificatePEM: cert,
				Performance: &HY2Performance{Obfs: &HY2Obfs{Type: "salamander", Password: "hy2-remote-obfs-secret"}, HopPorts: "30000-31000", HopInterval: "20s"}}},
	}

	// Route TCP-only PortForward through HTTP CONNECT egress, and proxy Nodes through UDP-capable egresses.
	st.Forwards = []PortForward{
		{ID: "f000000000000001", Name: "tcp-via-http", Listen: "127.0.0.1", Port: 31001, Network: "tcp", TargetHost: "198.51.100.99", TargetPort: 443, EgressID: "e000000000000002", Enabled: true},
	}
	for idx, eid := range []string{
		"e000000000000003", "e000000000000004", "e000000000000005", "e000000000000006",
		"e000000000000007", "e000000000000008", "e000000000000009", "e00000000000000a", "e00000000000000b",
	} {
		ssIn := NewShadowsocks()
		inNode := Node{
			ID: fmt.Sprintf("a00000000000000%d", idx+1), Name: fmt.Sprintf("in-%d", idx+1),
			Protocol: "ss2022", Host: "198.51.100.1", Listen: "127.0.0.1", Port: 41000 + idx,
			Enabled: true, Shadowsocks: ssIn, EgressID: eid,
		}
		inNode.Users = []User{NewUserForNode("u", inNode)}
		st.Nodes = append(st.Nodes, inNode)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("all-egress topology failed validation: %v", err)
	}
	srvCfg, err := Server(st, t.TempDir())
	if err != nil {
		t.Fatalf("Server() render failed for all-egress topology: %v", err)
	}
	srvCfg = compactJSONBytes(t, srvCfg)
	for _, wantSub := range []string{
		`"type":"http"`, `"type":"trojan"`, `"type":"vless"`, `"type":"vmess"`,
		`"type":"anytls"`, `"type":"tuic"`, `"type":"hysteria2"`, `"server_ports":["30000:31000"]`,
	} {
		if !bytes.Contains(srvCfg, []byte(wantSub)) {
			t.Fatalf("Server() output missing %s:\n%s", wantSub, srvCfg)
		}
	}

	// Verify HTTP egress rejects UDP=true and rejects binding a UDP-capable proxy Node.
	badHTTPUDP := st.Clone()
	badHTTPUDP.Egresses[0].UDP = true
	if err := badHTTPUDP.Validate(); err == nil {
		t.Fatal("HTTP CONNECT egress must reject UDP=true")
	}
	badNodeViaHTTP := st.Clone()
	badNodeViaHTTP.Nodes[0].EgressID = "e000000000000001"
	if err := badNodeViaHTTP.Validate(); err == nil {
		t.Fatal("UDP-capable proxy Node must reject TCP-only HTTP CONNECT egress")
	}

	// Verify Redact hides all newly added remote secrets.
	leakSample := strings.Join([]string{
		"http-secret-password-01", "https-secret-password-02", aes128Key,
		"ssaead-secret-password-04", "trojan-secret-password-05", uuidSample,
		"anytls-secret-password-08", "tuic-secret-password-09", "hy2-remote-obfs-secret",
	}, " | ")
	scrubbed := Redact(leakSample, st)
	for _, secret := range []string{
		"http-secret-password-01", "https-secret-password-02",
		"ssaead-secret-password-04", "trojan-secret-password-05", uuidSample,
		"anytls-secret-password-08", "tuic-secret-password-09", "hy2-remote-obfs-secret",
	} {
		if strings.Contains(scrubbed, secret) {
			t.Fatalf("remote secret %q leaked through Redact: %s", secret, scrubbed)
		}
	}
}

func TestRound3RealityMultiShortIDGRPCFingerprintsAndProbe(t *testing.T) {
	rBase, err := NewReality("www.microsoft.com", "www.microsoft.com:443")
	if err != nil {
		t.Fatal(err)
	}
	rBase.ShortID = "01020304"
	u := NewUser("u1", "reality")

	// 1. Zero runtime Server() diff when ShortIDs is nil/empty vs single ShortID.
	stLegacy := NewState()
	stLegacy.Nodes = []Node{{
		ID: "9999999999999991", Name: "r-legacy", Protocol: "reality",
		Host: "198.51.100.50", Listen: "0.0.0.0", Port: 443, Enabled: true,
		Reality: rBase, Users: []User{u},
	}}
	srvLegacy, err := Server(stLegacy, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srvLegacy = compactJSONBytes(t, srvLegacy)
	if !bytes.Contains(srvLegacy, []byte(`"short_id":["01020304"]`)) {
		t.Fatalf("unexpected legacy REALITY short_id rendering: %s", srvLegacy)
	}

	// Multi-short_id emits all IDs in server inbound while client uses primary ShortID.
	rMulti := *rBase
	rMulti.ShortIDs = []string{"01020304", "deadbeef", "cafebabe"}
	stMulti := stLegacy.Clone()
	stMulti.Nodes[0].Reality = &rMulti
	if err := stMulti.Validate(); err != nil {
		t.Fatalf("valid multi-short_id rejected: %v", err)
	}
	srvMulti, err := Server(stMulti, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srvMulti = compactJSONBytes(t, srvMulti)
	if !bytes.Contains(srvMulti, []byte(`"short_id":["01020304","deadbeef","cafebabe"]`)) {
		t.Fatalf("multi-short_id server inbound mismatch: %s", srvMulti)
	}
	outMulti, _ := json.Marshal(Outbound(stMulti.Nodes[0], u))
	if !bytes.Contains(outMulti, []byte(`"short_id":"01020304"`)) {
		t.Fatalf("client outbound should use primary short_id: %s", outMulti)
	}

	// Reject ShortIDs missing primary ShortID, uppercase hex, duplicates, or >16 items.
	for _, badSIDs := range [][]string{
		{"deadbeef", "cafebabe"}, // missing primary 01020304
		{"01020304", "DEADBEEF"}, // uppercase
		{"01020304", "01020304"}, // duplicate
		{"01020304", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "10"}, // 17 items
	} {
		cand := stMulti.Clone()
		cand.Nodes[0].Reality.ShortIDs = badSIDs
		if err := cand.Validate(); err == nil {
			t.Fatalf("accepted invalid REALITY ShortIDs: %v", badSIDs)
		}
	}

	// 2. Extended fingerprints + REALITY + gRPC (no Vision flow).
	for _, fp := range []string{"chrome", "firefox", "safari", "ios", "edge", "random", "randomized", "qq", "android", "360"} {
		cand := stLegacy.Clone()
		cand.Nodes[0].Reality.Fingerprint = fp
		cand.Nodes[0].Transport = &TransportOptions{Type: "grpc", ServiceName: "reality_service"}
		if err := cand.Validate(); err != nil {
			t.Fatalf("REALITY + gRPC + fingerprint %s rejected: %v", fp, err)
		}
	}
	grpcNode := stLegacy.Nodes[0]
	grpcNode.Transport = &TransportOptions{Type: "grpc", ServiceName: "reality_service"}
	stGRPC := NewState()
	stGRPC.Nodes = []Node{grpcNode}
	srvGRPC, err := Server(stGRPC, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srvGRPC = compactJSONBytes(t, srvGRPC)
	if bytes.Contains(srvGRPC, []byte("xtls-rprx-vision")) || !bytes.Contains(srvGRPC, []byte(`"service_name":"reality_service"`)) {
		t.Fatalf("REALITY+gRPC server inbound must omit Vision flow and include gRPC service_name: %s", srvGRPC)
	}
	mhGRPC, err := Export(grpcNode, u, "mihomo")
	if err != nil || bytes.Contains(mhGRPC, []byte("xtls-rprx-vision")) || !bytes.Contains(mhGRPC, []byte("grpc-service-name: reality_service")) {
		t.Fatalf("REALITY+gRPC mihomo export mismatch: %v\n%s", err, mhGRPC)
	}
	uriGRPC, err := Export(grpcNode, u, "uri")
	if err != nil || bytes.Contains(uriGRPC, []byte("xtls-rprx-vision")) || !bytes.Contains(uriGRPC, []byte("type=grpc")) || !bytes.Contains(uriGRPC, []byte("serviceName=reality_service")) {
		t.Fatalf("REALITY+gRPC URI export mismatch: %v %s", err, uriGRPC)
	}

	// 3. RealityTargetPolicy & ProbeReality: shared CDN/PaaS exclusions + X25519 CurveID enforcement.
	for _, cdnHost := range []string{
		"app.workers.dev", "d111111abcdef8.cloudfront.net", "demo.global.ssl.fastly.net",
		"my-site.vercel.app", "my-site.netlify.app", "org.github.io", "my-app.herokuapp.com",
		"service.onrender.com", "app.fly.dev", "web.up.railway.app", "site.azurewebsites.net",
	} {
		if err := RealityTargetPolicy(&Reality{ServerName: cdnHost, Target: cdnHost + ":443"}); err == nil {
			t.Fatalf("RealityTargetPolicy accepted shared multi-tenant CDN/PaaS host %s", cdnHost)
		}
	}

	cert, key := makeCert(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cert)) {
		t.Fatal("failed to append test cert")
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	loopbackIPs := func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	resolveOK := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return resolveRealityWith(ctx, host, func(context.Context, string) (string, error) {
			return "localhost.", nil
		}, loopbackIPs)
	}
	resolveVercelCNAME := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return resolveRealityWith(ctx, host, func(context.Context, string) (string, error) {
			return "cname.vercel-dns.com.", nil
		}, loopbackIPs)
	}

	// Server negotiating ONLY P-256 must be rejected by probeReality.
	p256Srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	p256Srv.EnableHTTP2 = true
	p256Srv.TLS = &tls.Config{
		Certificates:     []tls.Certificate{pair},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
	}
	p256Srv.StartTLS()
	defer p256Srv.Close()

	_, p256Port, _ := net.SplitHostPort(p256Srv.Listener.Addr().String())
	_, err = probeReality(context.Background(), &Reality{ServerName: "localhost", Target: "localhost:" + p256Port}, resolveOK, dialer.DialContext, roots)
	if err == nil || !strings.Contains(err.Error(), "X25519") {
		t.Fatalf("probeReality should reject P-256-only TLS 1.3 server, got: %v", err)
	}

	// Server negotiating X25519 passes probeReality, unless CNAME points to a multi-tenant CDN!
	x25519Srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	x25519Srv.EnableHTTP2 = true
	x25519Srv.TLS = &tls.Config{
		Certificates:     []tls.Certificate{pair},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"h2", "http/1.1"},
	}
	x25519Srv.StartTLS()
	defer x25519Srv.Close()

	_, xPort, _ := net.SplitHostPort(x25519Srv.Listener.Addr().String())
	if _, err := probeReality(context.Background(), &Reality{ServerName: "localhost", Target: "localhost:" + xPort}, resolveOK, dialer.DialContext, roots); err != nil {
		t.Fatalf("probeReality rejected valid TLS 1.3 + H2 + X25519 server: %v", err)
	}
	if _, err := probeReality(context.Background(), &Reality{ServerName: "localhost", Target: "localhost:" + xPort}, resolveVercelCNAME, dialer.DialContext, roots); err == nil {
		t.Fatal("probeReality accepted custom domain CNAMEing to multi-tenant Vercel DNS")
	}
}

func TestRound3Schema9RejectsSmuggledRound3Fields(t *testing.T) {
	baseS9 := `{
  "schema": 9,
  "core_version": "1.14.0",
  "nodes": [
    {
      "id": "1111111111111111",
      "name": "legacy-r",
      "protocol": "reality",
      "host": "198.51.100.1",
      "listen": "0.0.0.0",
      "port": 443,
      "connect_port": 443,
      "enabled": true,
      "users": [{"id": "u1", "name": "default", "uuid": "5d40abb5-41bc-4f04-95ed-6f1e5b80a25f"}],
      "reality": {
        "server_name": "www.microsoft.com",
        "target": "www.microsoft.com:443",
        "private_key": "eC0xMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA",
        "public_key": "eC0xMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTE",
        "short_id": "01020304",
        "fingerprint": "chrome"
      }
    }
  ],
  "egresses": [
    {
      "id": "2222222222222222",
      "name": "legacy-socks",
      "protocol": "socks5",
      "server": "198.51.100.2",
      "port": 1080,
      "udp": false,
      "socks": {}
    }
  ]
}`
	if _, err := DecodeState([]byte(baseS9)); err != nil {
		t.Fatalf("clean schema 9 state rejected by DecodeState: %v", err)
	}

	smuggledReplacements := [][2]string{
		{`"short_id": "01020304"`, `"short_id": "01020304", "short_ids": ["01020304"]`},
		{`"short_id": "01020304"`, `"short_id": "01020304", "short_ids": null`},
		{`"short_id": "01020304"`, `"short_id": "01020304", "ſhort_ids": null`},
		{`"fingerprint": "chrome"`, `"fingerprint": "qq"`},
		{`"enabled": true,`, `"enabled": true, "multiplex": {"enabled": true},`},
		{`"enabled": true,`, `"enabled": true, "Multiplex": null,`},
		{`"enabled": true,`, `"enabled": true, "transport": {"type": "grpc", "service_name": "grpc"},`},
		{`"udp": false,`, `"udp": false, "transport": null,`},
		{`"udp": false,`, `"udp": false, "multiplex": null,`},
		{`"socks": {}`, `"http": {}`},
		{`"socks": {}`, `"socks": {}, "trojan": null`},
		{`"socks": {}`, `"socks": {}, "vless": null`},
		{`"socks": {}`, `"socks": {}, "vmess": null`},
		{`"socks": {}`, `"socks": {}, "anytls": null`},
		{`"socks": {}`, `"socks": {}, "tuic": null`},
	}
	for _, tc := range smuggledReplacements {
		mutated := strings.Replace(baseS9, tc[0], tc[1], 1)
		if _, err := DecodeState([]byte(mutated)); err == nil {
			t.Fatalf("schema 9 accepted smuggled Round 3 mutation: %s", tc[1])
		}
	}
}

func TestRound3OfficialCoreCheckAndEndToEndLoopback(t *testing.T) {
	singBin := os.Getenv("SING_BOX_BIN")
	if singBin == "" {
		t.Skip("set SING_BOX_BIN to a verified official sing-box 1.14.x binary")
	}
	mihomoBin := os.Getenv("MIHOMO_BIN")

	cert, key := makeCert(t)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("reality-cover"))
	}))
	realityTarget.EnableHTTP2 = true
	realityTarget.TLS = &tls.Config{
		Certificates:     []tls.Certificate{pair},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"h2", "http/1.1"},
	}
	realityTarget.StartTLS()
	defer realityTarget.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("round3-proxy-ok"))
	}))
	defer origin.Close()

	rGRPC, err := NewReality("localhost", realityTarget.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rGRPC.Fingerprint = "qq"
	rGRPC.ShortID = "01020304"
	rGRPC.ShortIDs = []string{"01020304", "deadbeef"}

	ss128, err := NewShadowsocks2022(SS2022AES128Method)
	if err != nil {
		t.Fatal(err)
	}
	tlsLocal := &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert, KeyPEM: key}

	nRealityGRPC := Node{
		ID: Token(8), Name: "R3-REALITY-gRPC", Protocol: "reality",
		Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		Transport: &TransportOptions{Type: "grpc", ServiceName: "r3grpc"},
		Reality:   rGRPC, Users: []User{NewUser("u", "reality")},
	}
	nVLESSH2 := Node{
		ID: Token(8), Name: "R3-VLESS-H2", Protocol: "vless-tls",
		Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		Transport:   &TransportOptions{Type: "http", Path: "/r3h2", Host: "localhost"},
		Certificate: tlsLocal, Users: []User{NewUser("u", "vless-tls")},
	}
	nTrojanWSMux := Node{
		ID: Token(8), Name: "R3-Trojan-WS-Mux", Protocol: "trojan",
		Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		Transport:   &TransportOptions{Type: "ws", Path: "/r3ws", MaxEarlyData: 2048},
		Multiplex:   &MultiplexOptions{Enabled: true, Protocol: "yamux", MaxConnections: 2, MinStreams: 4, Padding: true},
		Certificate: tlsLocal, Users: []User{NewUser("u", "trojan")},
	}
	nSS128Mux := Node{
		ID: Token(8), Name: "R3-SS2022-128-Mux", Protocol: "ss2022",
		Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		Multiplex:   &MultiplexOptions{Enabled: true, Protocol: "h2mux", MaxConnections: 2},
		Shadowsocks: ss128,
	}
	nSS128Mux.Users = []User{NewUserForNode("u", nSS128Mux)}

	nHY2Obfs := Node{
		ID: Token(8), Name: "R3-HY2-Salamander", Protocol: "hysteria2",
		Host: "127.0.0.1", Listen: "127.0.0.1", Port: freePort(t), Enabled: true,
		HY2:         &HY2Performance{Obfs: &HY2Obfs{Type: "salamander", Password: "r3-salamander-obfs-key"}},
		Certificate: tlsLocal, Users: []User{NewUser("u", "hysteria2")},
	}

	s := NewState()
	s.Nodes = []Node{nRealityGRPC, nVLESSH2, nTrojanWSMux, nSS128Mux, nHY2Obfs}
	if err := s.Validate(); err != nil {
		t.Fatalf("Round 3 loopback state invalid: %v", err)
	}
	srvBytes, err := Server(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, singBin, srvBytes)

	for _, n := range s.Nodes {
		n := n
		t.Run(n.Name, func(t *testing.T) {
			if mihomoBin != "" {
				mhBytes, err := Export(n, n.Users[0], "mihomo")
				if err != nil {
					t.Fatalf("Mihomo export failed: %v", err)
				}
				mhDir := t.TempDir()
				mhFile := filepath.Join(mhDir, "config.yaml")
				if err := os.WriteFile(mhFile, mhBytes, 0600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(mihomoBin, "-d", mhDir, "-f", mhFile, "-t").CombinedOutput(); err != nil {
					t.Fatalf("mihomo -t rejected %s:\n%s\n%s", n.Name, out, mhBytes)
				}
			}

			clientPort := freePort(t)
			cfg := Client(n, n.Users[0], clientPort)
			if ProtocolRequiresCertificate(n.Protocol) {
				cfg["outbounds"].([]any)[0].(M)["tls"].(M)["certificate"] = []string{cert}
			}
			rawCfg, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, singBin, rawCfg)

			proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(clientPort))
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr, Timeout: 8 * time.Second}

			var resp *http.Response
			var reqErr error
			for attempt := 0; attempt < 10; attempt++ {
				resp, reqErr = hc.Get(origin.URL)
				if reqErr == nil {
					break
				}
				time.Sleep(150 * time.Millisecond)
			}
			if reqErr != nil {
				t.Fatalf("HTTP proxy roundtrip failed for %s: %v", n.Name, reqErr)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "round3-proxy-ok" {
				t.Fatalf("unexpected proxy payload for %s: err=%v body=%q", n.Name, err, body)
			}
		})
	}

	// Also verify sing-box check accepts the 11-egress topology Server() config!
	egressCheckDir := t.TempDir()
	allEgressState := buildAllEgressCheckState(t, cert)
	allEgressBytes, err := Server(allEgressState, egressCheckDir)
	if err != nil {
		t.Fatal(err)
	}
	allEgressPath := filepath.Join(egressCheckDir, "server.json")
	if err := os.WriteFile(allEgressPath, allEgressBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(singBin, "check", "-c", allEgressPath).CombinedOutput(); err != nil {
		t.Fatalf("official sing-box check rejected 11-egress server config: %v\n%s\n%s", err, out, allEgressBytes)
	}
}

func buildAllEgressCheckState(t *testing.T, cert string) State {
	t.Helper()
	rSample, err := NewReality("www.microsoft.com", "www.microsoft.com:443")
	if err != nil {
		t.Fatal(err)
	}
	u := NewUser("u", "vless-tls").UUID
	minIdle := 1
	st := NewState()
	st.Egresses = []Egress{
		{ID: "c000000000000001", Name: "socks", Protocol: "socks5", Server: "198.51.100.10", Port: 1080, UDP: true, Socks: &RemoteSOCKS{Username: "u", Password: "p"}},
		{ID: "c000000000000002", Name: "https", Protocol: "http", Server: "198.51.100.11", Port: 8443, UDP: false, HTTP: &RemoteHTTP{Username: "u", Password: "p", TLS: true, ServerName: "proxy.example.com", CertificatePEM: cert}},
		{ID: "c000000000000003", Name: "r-grpc", Protocol: "reality", Server: "198.51.100.12", Port: 443, UDP: true, Transport: &TransportOptions{Type: "grpc", ServiceName: "grpc"}, Reality: &RemoteReality{UUID: u, ServerName: "www.microsoft.com", PublicKey: rSample.PublicKey, ShortID: "0102", Fingerprint: "android"}},
		{ID: "c000000000000004", Name: "ss128", Protocol: "ss2022", Server: "198.51.100.13", Port: 8388, UDP: true, Multiplex: &MultiplexOptions{Enabled: true, Protocol: "h2mux"}, Shadowsocks: &RemoteSS{Method: SS2022AES128Method, Password: ssKeyBytes(16) + ":" + ssKeyBytes(16)}},
		{ID: "c000000000000005", Name: "ssaead", Protocol: "ss-aead", Server: "198.51.100.14", Port: 8389, UDP: true, Shadowsocks: &RemoteSS{Method: "aes-256-gcm", Password: "remote-ssaead-secret-1234"}},
		{ID: "c000000000000006", Name: "hy2hop", Protocol: "hysteria2", Server: "198.51.100.15", Port: 8443, UDP: true, HY2: &RemoteHY2{Password: "remote-hy2-secret-1234", ServerName: "hy2.example.com", CertificatePEM: cert, Performance: &HY2Performance{Obfs: &HY2Obfs{Type: "salamander", Password: "remote-hy2-obfs-5678"}, HopPorts: "20000-25000", HopInterval: "30s"}}},
		{ID: "c000000000000007", Name: "trojan", Protocol: "trojan", Server: "198.51.100.16", Port: 443, UDP: true, Transport: &TransportOptions{Type: "ws", Path: "/tr", MaxEarlyData: 2048}, Multiplex: &MultiplexOptions{Enabled: true, Protocol: "yamux", Padding: true}, Trojan: &RemoteTrojan{Password: "remote-trojan-secret-1234", ServerName: "tr.example.com", CertificatePEM: cert}},
		{ID: "c000000000000008", Name: "vlessh2", Protocol: "vless-tls", Server: "198.51.100.17", Port: 443, UDP: true, Transport: &TransportOptions{Type: "http", Path: "/h2", Host: "vl.example.com"}, VLESS: &RemoteVLESS{UUID: u, ServerName: "vl.example.com", PacketEncoding: "xudp", CertificatePEM: cert}},
		{ID: "c000000000000009", Name: "vmess", Protocol: "vmess-tls", Server: "198.51.100.18", Port: 443, UDP: true, Transport: &TransportOptions{Type: "httpupgrade", Path: "/up"}, VMess: &RemoteVMess{UUID: u, Security: "auto", ServerName: "vm.example.com", CertificatePEM: cert}},
		{ID: "c00000000000000a", Name: "anytls", Protocol: "anytls", Server: "198.51.100.19", Port: 443, UDP: true, AnyTLS: &RemoteAnyTLS{Password: "remote-anytls-secret-1234", ServerName: "at.example.com", MinIdleSession: &minIdle, CertificatePEM: cert}},
		{ID: "c00000000000000b", Name: "tuic", Protocol: "tuic", Server: "198.51.100.20", Port: 8443, UDP: true, TUIC: &RemoteTUIC{UUID: u, Password: "remote-tuic-secret-1234", ServerName: "tu.example.com", CongestionControl: "bbr", UDPRelayMode: "native", Heartbeat: "10s", CertificatePEM: cert}},
	}
	st.Forwards = []PortForward{
		{ID: "d000000000000001", Name: "https-fwd", Listen: "127.0.0.1", Port: 32001, Network: "tcp", TargetHost: "198.51.100.90", TargetPort: 443, EgressID: "c000000000000002", Enabled: true},
	}
	for i, e := range st.Egresses {
		if !e.UDP {
			continue
		}
		ssIn := NewShadowsocks()
		n := Node{
			ID: fmt.Sprintf("b0000000000000%02x", i+1), Name: fmt.Sprintf("in-%d", i+1),
			Protocol: "ss2022", Host: "198.51.100.1", Listen: "127.0.0.1", Port: 42000 + i,
			Enabled: true, Shadowsocks: ssIn, EgressID: e.ID,
		}
		n.Users = []User{NewUserForNode("u", n)}
		st.Nodes = append(st.Nodes, n)
	}
	return st
}
