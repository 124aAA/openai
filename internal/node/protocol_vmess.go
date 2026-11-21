package node

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
)

func vmessTLSCredential(u *User) {
	realityCredential(u)
	u.Password = ""
}

func validateVMessTLS(n Node) error { return validateTLSUUIDNode(n, true) }

func vmessTLSInbound(n Node, root string) M {
	u := make([]any, 0, len(n.Users))
	for _, x := range n.Users {
		u = append(u, M{"name": x.ID, "uuid": x.UUID, "alterId": 0})
	}
	out := M{"type": "vmess", "users": u, "tls": tlsInboundWithTransport(n, root)}
	if tr := transportInbound(n); tr != nil {
		out["transport"] = tr
	}
	if mux := multiplexInbound(n.Multiplex); mux != nil {
		out["multiplex"] = mux
	}
	return out
}

func vmessTLSURI(n Node, u User) string {
	q := url.Values{
		"encryption":    {"auto"},
		"security":      {"tls"},
		"sni":           {n.Certificate.ServerName},
		"allowInsecure": {"0"},
	}
	applyTransportURIQuery(q, n)
	x := url.URL{
		Scheme:   "vmess",
		User:     url.User(u.UUID),
		Host:     net.JoinHostPort(n.Host, strconv.Itoa(EffectiveConnectPort(n))),
		RawQuery: q.Encode(),
		Fragment: n.Name + " / " + u.Name,
	}
	return x.String()
}

// VMessV2RayNURI returns the V2RayN v2 JSON Base64 sharing URI for clients
// that expect the legacy JSON-encoded vmess:// link.
func VMessV2RayNURI(n Node, u User) string {
	return VMessV2RayNURIWithName(n, u, n.Name+" / "+u.Name)
}

func VMessV2RayNURIWithName(n Node, u User, ps string) string {
	netType := EffectiveTransport(n)
	path := ""
	host := ""
	alpn := ""
	if n.Transport != nil {
		switch netType {
		case "ws":
			path = n.Transport.Path
			if n.Transport.MaxEarlyData > 0 {
				path += "?ed=" + strconv.Itoa(n.Transport.MaxEarlyData)
			}
			host = n.Transport.Host
			alpn = "http/1.1"
		case "httpupgrade":
			path = n.Transport.Path
			host = n.Transport.Host
			alpn = "http/1.1"
		case "http":
			netType = "h2"
			path = n.Transport.Path
			host = n.Transport.Host
			alpn = "h2"
		case "grpc":
			path = n.Transport.ServiceName
			alpn = "h2"
		}
	}
	sni := ""
	if n.Certificate != nil {
		sni = n.Certificate.ServerName
	}
	payload := map[string]string{
		"v":    "2",
		"ps":   ps,
		"add":  n.Host,
		"port": strconv.Itoa(EffectiveConnectPort(n)),
		"id":   u.UUID,
		"aid":  "0",
		"scy":  "auto",
		"net":  netType,
		"type": "none",
		"host": host,
		"path": path,
		"tls":  "tls",
		"sni":  sni,
		"alpn": alpn,
	}
	raw, _ := json.Marshal(payload)
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

func vmessTLSOutbound(n Node, u User) M {
	out := M{
		"type":                 "vmess",
		"uuid":                 u.UUID,
		"security":             "auto",
		"alter_id":             0,
		"global_padding":       true,
		"authenticated_length": true,
		"packet_encoding":      "xudp",
		"tls":                  tlsOutboundWithTransport(n),
	}
	if tr := transportOutbound(n); tr != nil {
		out["transport"] = tr
	}
	if mux := multiplexOutbound(n.Multiplex); mux != nil {
		out["multiplex"] = mux
	}
	return out
}

func vmessTLSMihomo(n Node, u User) M {
	out := M{
		"type":             "vmess",
		"uuid":             u.UUID,
		"alterId":          0,
		"cipher":           "auto",
		"tls":              true,
		"udp":              true,
		"servername":       n.Certificate.ServerName,
		"skip-cert-verify": false,
		"network":          "tcp",
	}
	applyTransportMihomo(out, n)
	applyMultiplexMihomo(out, n.Multiplex)
	return out
}
