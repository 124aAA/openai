package node

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is real HY2 transport with an Ed25519 server leaf and an explicitly
// selected native QUIC client. It does not change a user's fingerprint choice.
// The caller supplies each separately verified official 1.14.0/1.14.3 binary.
func TestOfficialCoreHY2Ed25519ExplicitNativeQUICAndDefaultClientGate(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("requires a verified official SING_BOX_BIN for Ed25519 HY2 TCP/UDP")
	}
	version, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(version), "sing-box version 1.14.0\n") && !strings.Contains(string(version), "sing-box version 1.14.3\n") {
		t.Fatal("Ed25519 interoperability test requires the separately pinned compatible cores")
	}
	t.Logf("actual core: %s", strings.Split(string(version), "\n")[0])
	s := certificateEd25519Fixture(t)
	s.Nodes[0].Port = freePort(t)
	n := s.Nodes[0]
	u := n.Users[0]
	server, err := Server(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, server)
	exported, err := ExportWithCapabilities(n, u, "sing-box", strings.TrimPrefix(strings.Split(string(version), "\n")[0], "sing-box version "), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var client M
	if err = json.Unmarshal(exported.Data, &client); err != nil {
		t.Fatal(err)
	}
	proxyPort := freePort(t)
	client["inbounds"].([]any)[0].(map[string]any)["listen_port"] = proxyPort
	outbound := client["outbounds"].([]any)[0].(map[string]any)
	if outbound["disable_chrome_parrot"] != true {
		t.Fatal("explicit native QUIC choice was not preserved")
	}
	outbound["tls"].(map[string]any)["certificate"] = []string{n.Certificate.CertPEM}
	raw, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, raw)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "controlled-ed25519-hy2-https-payload")
	}))
	defer origin.Close()
	transport := origin.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
	transport.Proxy = http.ProxyURL(proxy)
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := httpClient.Get(origin.URL)
	if err != nil {
		t.Fatal("real Ed25519 HY2 proxied HTTPS failed", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || string(body) != "controlled-ed25519-hy2-https-payload" {
		t.Fatalf("real Ed25519 HY2 HTTPS payload failed: status=%d bytes=%d error=%v", response.StatusCode, len(body), readErr)
	}
	socksUDP(t, proxyPort)
	selected := n
	selected.HY2 = nil
	if _, err = ExportWithCapabilities(selected, u, "sing-box", "1.14.3", nil, true); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Fatal("default Chrome Ed25519 client gate was bypassed", err)
	}
	t.Log("real exported complete configuration carried verified HTTPS and controlled UDP echo; explicit disable_chrome_parrot=true retained, default Chrome configuration rejected before execution")
}
