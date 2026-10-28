package node

// Persist server and client choices independently. The first Batch09 schema
// reserves no raw core fields: only these explicitly supported options enter it.
type TUICOptions struct {
	ServerCongestionControl string `json:"server_congestion_control,omitempty"`
	ClientCongestionControl string `json:"client_congestion_control,omitempty"`
	AuthTimeout             string `json:"auth_timeout,omitempty"`
	ServerHeartbeat         string `json:"server_heartbeat,omitempty"`
	ClientHeartbeat         string `json:"client_heartbeat,omitempty"`
	UDPRelayMode            string `json:"udp_relay_mode,omitempty"`
	ZeroRTTHandshake        *bool  `json:"zero_rtt_handshake,omitempty"`
}
