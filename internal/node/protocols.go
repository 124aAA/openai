package node

import "sort"

// Protocol adapters own authentication, validation and wire/client formats.
// The store, backup, firewall and systemd code depend only on this contract.
type Adapter struct {
	Networks   []string
	Credential func(*User)
	Validate   func(Node) error
	Inbound    func(Node, string) M
	URI        func(Node, User) string
	Outbound   func(Node, User) M
	Mihomo     func(Node, User) M
}

var adapters = map[string]Adapter{
	"reality":   {[]string{"tcp"}, realityCredential, validateReality, realityInbound, realityURI, realityOutbound, realityMihomo},
	"hysteria2": {[]string{"udp"}, hysteriaCredential, validateHysteria, hysteriaInbound, hysteriaURI, hysteriaOutbound, hysteriaMihomo},
	"ss2022":    {[]string{"tcp", "udp"}, ssCredential, validateSS2022, ssInbound, ssURI, ssOutbound, ssMihomo},
}

func Protocol(name string) (Adapter, bool) { p, ok := adapters[name]; return p, ok }
func Protocols() []string {
	names := make([]string, 0, len(adapters))
	for name := range adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
