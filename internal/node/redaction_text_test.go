package node

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactTextCredentialsWithoutState(t *testing.T) {
	const uuid = "23ED7C8A-9C72-4E18-8522-347785A4D5B0"
	tests := []struct {
		name, input, secret string
	}{
		{"info UUID", "UUID：" + uuid, uuid},
		{"unlabelled UUID", "client " + uuid + " rejected", uuid},
		{"info private key", "Reality Private Key：server-private-key", "server-private-key"},
		{"English password", "Password: plain-secret", "plain-secret"},
		{"SS2022 password", "Password：server-part:client-part", "server-part:client-part"},
		{"complex password", "密码 = complex:@/?#%中文 password", "complex:@/?#%中文 password"},
		{"server key", "服务密钥：server-secret", "server-secret"},
		{"Chinese private key", "私钥: private-secret", "private-secret"},
		{"indented assignment", "\tPRIVATE_KEY = assigned-secret", "assigned-secret"},
		{"server key assignment", "server_key=assigned-server-secret", "assigned-server-secret"},
		{"key PEM assignment", "key_pem: encoded-key-secret", "encoded-key-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if strings.Contains(got, tt.secret) || !strings.Contains(got, "已隐藏") {
				t.Fatalf("credential was not hidden: %q", got)
			}
			if tt.name == "SS2022 password" && (strings.Contains(got, "server-part") || strings.Contains(got, "client-part")) {
				t.Fatal("part of the composed SS2022 password leaked")
			}
		})
	}
}

func TestRedactTextPreservesDiagnosticsAndLineBoundaries(t *testing.T) {
	const diagnostics = "[ERROR] authentication failed: password mismatch\n" +
		"private key validation failed: invalid encoding\n" +
		"密码校验失败：长度不足\nReality Public Key：diagnostic-public-key\n" +
		"SNI：example.com\n握手目标：example.com:443\n"
	input := "Password:\n" + diagnostics + "Password：server:client\r\n" + diagnostics
	got := Redact(input)
	if strings.Count(got, diagnostics) != 2 || strings.Count(got, "\n") != strings.Count(input, "\n") {
		t.Fatalf("diagnostic lines were changed or consumed: %q", got)
	}
	if strings.Contains(got, "server:client") {
		t.Fatal("credential leaked")
	}
}

func TestRedactTextKeepsJSONValidAndCoversURIs(t *testing.T) {
	input := `{"password":"escaped\"secret:part","private_key":"private-secret","server_key":"server-secret","public_key":"public-value","sni":"example.com"}`
	got := Redact(input)
	if !json.Valid([]byte(got)) {
		t.Fatalf("redacted JSON is invalid: %s", got)
	}
	for _, secret := range []string{"escaped", "private-secret", "server-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("JSON secret leaked: %s", got)
		}
	}
	if !strings.Contains(got, "public-value") || !strings.Contains(got, "example.com") {
		t.Fatal("public diagnostic fields were hidden")
	}
	for _, scheme := range []string{"vless", "hysteria2", "hy2", "ss", "tuic"} {
		if got := Redact(scheme + "://uri-secret@host:443\nconnection refused"); got != "[节点链接已隐藏]\nconnection refused" {
			t.Fatalf("URI redaction failed: %q", got)
		}
	}
}
