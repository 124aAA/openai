package node

// Egress stores remote authentication independently of locally issued Users.
// Exactly one protocol-specific settings object is accepted. No raw sing-box
// JSON or arbitrary Dial fields enter the persisted model.
type Egress struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Protocol    string             `json:"protocol"`
	Server      string             `json:"server,omitempty"`
	Port        int                `json:"port,omitempty"`
	Detour      string             `json:"detour,omitempty"`
	UDP         bool               `json:"udp"`
	Socks       *RemoteSOCKS       `json:"socks,omitempty"`
	Reality     *RemoteReality     `json:"reality,omitempty"`
	Shadowsocks *RemoteSS          `json:"shadowsocks,omitempty"`
	HY2         *RemoteHY2         `json:"hysteria2,omitempty"`
	WireGuard   *WireGuardEndpoint `json:"wireguard,omitempty"`
}
type RemoteSOCKS struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
type RemoteReality struct {
	UUID        string `json:"uuid"`
	ServerName  string `json:"server_name"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
type RemoteSS struct {
	Method   string `json:"method"`
	Password string `json:"password"`
}
type RemoteHY2 struct {
	Password       string          `json:"password"`
	ServerName     string          `json:"server_name"`
	CertificatePEM string          `json:"certificate_pem,omitempty"`
	Performance    *HY2Performance `json:"performance,omitempty"`
}

// WireGuardEndpoint is always userland (system:false). It never creates a host
// interface, changes routes, or edits existing peers. A listening landing endpoint
// must explicitly declare where received traffic goes through ReceiveEgressID.
type WireGuardEndpoint struct {
	Address         []string        `json:"address"`
	PrivateKey      string          `json:"private_key"`
	ListenPort      int             `json:"listen_port,omitempty"`
	MTU             int             `json:"mtu,omitempty"`
	Peers           []WireGuardPeer `json:"peers"`
	ReceiveEgressID string          `json:"receive_egress_id,omitempty"`
}
type WireGuardPeer struct {
	Address      string   `json:"address,omitempty"`
	Port         int      `json:"port,omitempty"`
	PublicKey    string   `json:"public_key"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"persistent_keepalive_interval,omitempty"`
}
type EgressPolicy struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Mode     string        `json:"mode"`
	Primary  string        `json:"primary"`
	Backup   string        `json:"backup,omitempty"`
	Selected string        `json:"selected,omitempty"`
	Health   *EgressHealth `json:"health,omitempty"`
}
type EgressHealth struct {
	URL               string `json:"url"`
	UDPAddress        string `json:"udp_address,omitempty"`
	FailureThreshold  int    `json:"failure_threshold"`
	RecoveryThreshold int    `json:"recovery_threshold"`
	CooldownSeconds   int    `json:"cooldown_seconds"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
}
type PortForward struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Listen     string `json:"listen"`
	Port       int    `json:"port"`
	Network    string `json:"network"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	EgressID   string `json:"egress_id,omitempty"`
	Enabled    bool   `json:"enabled"`
}

func EgressTag(id string) string  { return "egress-" + id }
func ForwardTag(id string) string { return "forward-" + id }

func (s *State) FindEgress(id string) (*Egress, error) {
	for i := range s.Egresses {
		if s.Egresses[i].ID == id {
			return &s.Egresses[i], nil
		}
	}
	for i := range s.Egresses {
		if s.Egresses[i].Name == id {
			return &s.Egresses[i], nil
		}
	}
	return nil, topologyError("出口不存在")
}
func (s *State) FindEgressPolicy(id string) (*EgressPolicy, error) {
	for i := range s.EgressPolicies {
		if s.EgressPolicies[i].ID == id {
			return &s.EgressPolicies[i], nil
		}
	}
	for i := range s.EgressPolicies {
		if s.EgressPolicies[i].Name == id {
			return &s.EgressPolicies[i], nil
		}
	}
	return nil, topologyError("出口策略不存在")
}
func (s *State) FindForward(id string) (*PortForward, error) {
	for i := range s.Forwards {
		if s.Forwards[i].ID == id {
			return &s.Forwards[i], nil
		}
	}
	for i := range s.Forwards {
		if s.Forwards[i].Name == id {
			return &s.Forwards[i], nil
		}
	}
	return nil, topologyError("中转不存在")
}

func ForwardNetworks(f PortForward) []string {
	switch f.Network {
	case "tcp":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	case "tcp+udp":
		return []string{"tcp", "udp"}
	}
	return nil
}
