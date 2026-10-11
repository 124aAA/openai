package node

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadStateSizeAndTrailingData(t *testing.T) {
	const limit = 8 << 20
	b, err := json.Marshal(NewState())
	if err != nil {
		t.Fatal(err)
	}
	exact := append(b, bytes.Repeat([]byte(" "), limit-len(b))...)
	tests := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"exact limit", exact, true},
		{"one byte over", append(append([]byte{}, exact...), ' '), false},
		{"hidden second JSON after limit", append(append([]byte{}, exact...), []byte(`{}`)...), false},
		{"second JSON within limit", append(append([]byte{}, b...), []byte(` {}`)...), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, tt.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadState(path); (err == nil) != tt.valid {
				t.Fatalf("ReadState error=%v, want valid=%v", err, tt.valid)
			}
		})
	}
}

func TestOversizedApplyPreservesCommittedStateAndService(t *testing.T) {
	st, backend := newStore(t)
	s := fixture(t)
	if err := st.WithLock(func() error { return st.Apply(s) }); err != nil {
		t.Fatal(err)
	}
	previous, _ := st.current()
	before, err := os.ReadFile(filepath.Join(st.Root, previous, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	activations := backend.activations
	cert, key := makeCert(t)
	next := s.Clone()
	n := &next.Nodes[0]
	n.Protocol, n.Reality = "hysteria2", nil
	n.Users = []User{NewUser("phone", "hysteria2")}
	n.Certificate = &Certificate{Mode: "pem", ServerName: "localhost", CertPEM: cert + strings.Repeat(" ", 8<<20), KeyPEM: key}
	if err := next.Validate(); err != nil {
		t.Fatal("oversized state must be structurally valid:", err)
	}
	if err := st.WithLock(func() error { return st.Apply(next) }); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatal("oversized candidate was not rejected by size limit:", err)
	}
	current, err := st.current()
	after, readErr := os.ReadFile(filepath.Join(st.Root, previous, "state.json"))
	if err != nil || readErr != nil || current != previous || !bytes.Equal(before, after) || backend.activations != activations || !backend.active {
		t.Fatal("oversized candidate changed committed state or service", err, readErr)
	}
	if _, err := os.Stat(filepath.Join(st.Root, "transaction.json")); !os.IsNotExist(err) {
		t.Fatal("oversized candidate left a transaction", err)
	}
	if got, err := st.Load(); err != nil || got.Nodes[0].Reality.PrivateKey != s.Nodes[0].Reality.PrivateKey {
		t.Fatal("committed state no longer readable or identity changed", err)
	}
}
