package node

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestOfficialCoreProjectDNSActuallyResolvesServerTarget(t *testing.T) {
	bin := os.Getenv("SING_BOX_BIN")
	if bin == "" {
		t.Skip("SING_BOX_BIN is unset; project resolver real-core path not run")
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "project-dns-controlled-target")
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	_, targetPort, _ := net.SplitHostPort(u.Host)
	for _, missing := range []bool{false, true} {
		name := "resolves"
		rcode := uint16(0)
		if missing {
			name = "nxdomain-fails"
			rcode = 3
		}
		t.Run(name, func(t *testing.T) {
			resolver, queries := controlledDNSServer(t, rcode, net.ParseIP("127.0.0.1"), nil, false)
			s := hyFixture(t)
			s.DNS = resolver
			s.Nodes[0].Port = freePort(t)
			n := s.Nodes[0]
			server, err := Server(s, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, server)
			port := freePort(t)
			client := Client(n, n.Users[0], port)
			client["outbounds"].([]any)[0].(M)["tls"].(M)["certificate"] = []string{n.Certificate.CertPEM}
			b, err := json.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, b)
			proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			hc := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := hc.Get("http://only-in-project-resolver.invalid:" + targetPort + "/object")
			if missing {
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 400 {
						t.Fatal("NXDOMAIN target unexpectedly succeeded")
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
				resp.Body.Close()
				if readErr != nil || string(payload) != "project-dns-controlled-target" {
					t.Fatal("project resolver path payload mismatch", readErr)
				}
			}
			if queries.Load() == 0 {
				t.Fatal("selected project DNS was never queried")
			}
		})
	}
}
