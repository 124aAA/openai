package main

import (
	"encoding/json"
	"os"
	"time"

	"qingnode/internal/node"
	"qingnode/internal/ui"
)

// Only explicitly selected public data belongs here. Never pass State, a
// remote credential, subscription material or raw command output to this path.
func queryJSON(kind string, data any) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		Version  int       `json:"version"`
		Kind     string    `json:"kind"`
		At       time.Time `json:"observed_at"`
		Location string    `json:"observation_location"`
		Data     any       `json:"data"`
	}{1, kind, time.Now().UTC(), "manager-configuration", data})
}

func publicQueryText(value string, state node.State) string {
	return ui.SanitizeText(node.Redact(value, state))
}

type publicEgress struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	UDPDeclared  bool   `json:"udp_declared"`
	Upstream     string `json:"upstream_id"`
	Availability string `json:"availability"`
}

type publicForward struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Network      string `json:"network"`
	Listen       string `json:"listen"`
	Target       string `json:"target"`
	Egress       string `json:"egress_id"`
	Enabled      bool   `json:"enabled"`
	Availability string `json:"availability"`
}

type publicEgressPolicy struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Mode         string `json:"mode"`
	Primary      string `json:"primary_id"`
	Backup       string `json:"backup_id"`
	Selected     string `json:"selected"`
	Availability string `json:"availability"`
}

type publicDevice struct {
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Strategy string               `json:"strategy"`
	Routing  string               `json:"routing"`
	Bindings []node.DeviceBinding `json:"bindings"`
	Disabled bool                 `json:"disabled"`
}

type publicSubscriptionRecord struct {
	DeviceID             string    `json:"device_id"`
	TokenID              string    `json:"token_id"`
	Revoked              bool      `json:"revoked"`
	ExpiresAt            time.Time `json:"expires_at"`
	PublishedFormatCount int       `json:"published_format_count"`
}

type publicSubscriptions struct {
	Configured bool                       `json:"configured"`
	Records    []publicSubscriptionRecord `json:"records"`
}
