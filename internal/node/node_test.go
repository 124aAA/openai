package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func fixture(t *testing.T) State {
	t.Helper()
	r, e := NewReality("www.example.com", "")
	if e != nil {
		t.Fatal(e)
	}
	s := NewState()
	s.Nodes = []Node{{ID: Token(8), Name: "香港 / A # % : true", Protocol: "reality", Host: "2001:db8::1", Listen: "::", Port: 443, Enabled: true, Users: []User{NewUser("手机用户", "reality")}, Reality: r}}
	return s
}
func TestExportsRoundTripAndNoServerPrivateKey(t *testing.T) {
	s := fixture(t)
	n := s.Nodes[0]
	u := n.Users[0]
	raw := URI(n, u)
	parsed, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if parsed.Hostname() != n.Host || parsed.Port() != "443" || parsed.User.Username() != u.UUID || parsed.Fragment != n.Name+" / "+u.Name {
		t.Fatalf("URI round trip failed: %s", raw)
	}
	for _, f := range []string{"uri", "qr", "base64", "mihomo", "provider", "sing-box"} {
		b, e := Export(n, u, f)
		if e != nil {
			t.Fatal(f, e)
		}
		if bytes.Contains(b, []byte(n.Reality.PrivateKey)) {
			t.Fatal("private key leaked", f)
		}
		if f == "mihomo" || f == "provider" {
			var doc map[string]any
			if e = yaml.Unmarshal(b, &doc); e != nil {
				t.Fatal(e)
			}
			p := doc["proxies"].([]any)[0].(map[string]any)
			if p["name"] != n.Name+" / "+u.Name {
				t.Fatal("YAML changed a scalar")
			}
		}
	}
	// Userinfo needs escaping independent from the fragment/query encoder.
	n.Protocol = "hysteria2"
	n.Certificate = &Certificate{ServerName: "example.com"}
	u.Password = "complex:@/?#%中文 password"
	parsed, e = url.Parse(URI(n, u))
	if e != nil || parsed.User.Username() != u.Password {
		t.Fatal("password not round-trippable")
	}
}
func TestCollisionValidationAndProtocolCoexistence(t *testing.T) {
	s := fixture(t)
	n := s.Nodes[0]
	n.ID = Token(8)
	n.Name = "second"
	s.Nodes = append(s.Nodes, n)
	if s.Validate() == nil {
		t.Fatal("duplicate TCP port accepted")
	}
	s.Nodes[1].Enabled = false
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	s.Nodes[0].Name = "bad\x1b[31m"
	if s.Validate() == nil {
		t.Fatal("terminal escape accepted")
	}
}

type fakeBackend struct {
	failCheck   bool
	failNext    bool
	active      bool
	activations int
	seen        []int
}

func (f *fakeBackend) Check(State, string) error {
	if f.failCheck {
		return errors.New("invalid config")
	}
	return nil
}
func (f *fakeBackend) Active() bool { return f.active }
func (f *fakeBackend) Activate(s State) error {
	f.activations++
	if len(s.Nodes) > 0 {
		f.seen = append(f.seen, s.Nodes[0].Port)
	}
	if f.failNext {
		f.failNext = false
		return errors.New("bind failed")
	}
	f.active = true
	return nil
}
func (f *fakeBackend) Stop() error { f.active = false; return nil }
func newStore(t *testing.T) (*Store, *fakeBackend) {
	f := &fakeBackend{}
	return &Store{Root: t.TempDir(), Backend: f, GID: -1}, f
}
func TestGenerationRollbackOnActivationFailure(t *testing.T) {
	st, b := newStore(t)
	s := fixture(t)
	e := st.WithLock(func() error { return st.Apply(s) })
	if e != nil {
		t.Fatal(e)
	}
	old, _ := st.current()
	s.Nodes[0].Port = 8443
	b.failNext = true
	e = st.WithLock(func() error { return st.Apply(s) })
	if e == nil {
		t.Fatal("expected apply failure")
	}
	current, _ := st.current()
	loaded, _ := st.Load()
	if current != old || loaded.Nodes[0].Port != 443 || !b.active {
		t.Fatal("old state/service was not recovered")
	}
	if _, e = os.Stat(filepath.Join(st.Root, "transaction.json")); !os.IsNotExist(e) {
		t.Fatal("transaction not cleared")
	}
}
func TestRejectedCandidateNeverRestartsAndRepeatIsNoOp(t *testing.T) {
	st, b := newStore(t)
	s := fixture(t)
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	g, _ := st.current()
	count := b.activations
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	g2, _ := st.current()
	if g != g2 || count != b.activations {
		t.Fatal("idempotency failed")
	}
	b.failCheck = true
	s.Nodes[0].Port++
	if st.WithLock(func() error { return st.Apply(s) }) == nil {
		t.Fatal("invalid accepted")
	}
	g2, _ = st.current()
	if g != g2 || count != b.activations {
		t.Fatal("validation touched service")
	}
}
func TestCrashRecoveryRollsBackUncommittedGeneration(t *testing.T) {
	st, b := newStore(t)
	s := fixture(t)
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	old, _ := st.current()
	s.Nodes[0].Port = 8443
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	next, _ := st.current()
	data, _ := json.Marshal(journal{Previous: old, Next: next, WasActive: true})
	if e := AtomicWrite(filepath.Join(st.Root, "transaction.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	if e := st.WithLock(func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	cur, _ := st.current()
	if cur != old || b.seen[len(b.seen)-1] != 443 {
		t.Fatal("crash recovery failed")
	}
}
func TestLockPreventsConcurrentReadModifyWrite(t *testing.T) {
	st, _ := newStore(t)
	if e := st.WithLock(func() error {
		other := &Store{Root: st.Root, Backend: OfflineBackend{}, GID: -1}
		if other.WithLock(func() error { t.Fatal("entered concurrent critical section"); return nil }) == nil {
			t.Fatal("concurrent lock accepted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestBackupAuthenticationAndNoPlaintext(t *testing.T) {
	s := fixture(t)
	b, e := Backup(s, "long test passphrase 2026")
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(s.Nodes[0].Reality.PrivateKey)) || bytes.Contains(b, []byte(s.Nodes[0].Users[0].UUID)) {
		t.Fatal("plaintext credential in backup")
	}
	restored, e := Restore(b, "long test passphrase 2026")
	if e != nil {
		t.Fatal(e)
	}
	if restored.Nodes[0].Reality.PrivateKey != s.Nodes[0].Reality.PrivateKey {
		t.Fatal("backup lost identity")
	}
	if _, e = Restore(b, "incorrect-password"); e == nil {
		t.Fatal("wrong password accepted")
	}
	b[len(b)-1] ^= 1
	if _, e = Restore(b, "long test passphrase 2026"); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestStateOwnershipAndPointerTraversal(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "existing-site.conf"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	st := &Store{Root: root, Backend: OfflineBackend{}, GID: -1}
	if st.WithLock(func() error { return nil }) == nil {
		t.Fatal("took over unrelated directory")
	}
	st, _ = newStore(t)
	if e := st.WithLock(func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../../etc", filepath.Join(st.Root, "current")); e != nil {
		t.Fatal(e)
	}
	if _, e := st.Load(); e == nil {
		t.Fatal("path traversal accepted")
	}
}
func TestRollbackPreservesUserIDsAndCredentials(t *testing.T) {
	st, _ := newStore(t)
	s := fixture(t)
	first := s.Clone()
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	first, _ = st.Load()
	s.Nodes[0].Users = append(s.Nodes[0].Users, NewUser("laptop", "reality"))
	s.Nodes[0].Port = 8443
	if e := st.WithLock(func() error { return st.Apply(s) }); e != nil {
		t.Fatal(e)
	}
	if e := st.WithLock(st.Rollback); e != nil {
		t.Fatal(e)
	}
	got, _ := st.Load()
	if got.Nodes[0].CreatedAt != first.Nodes[0].CreatedAt || got.Nodes[0].UpdatedAt == "" {
		t.Fatal("timestamps lost")
	}
	got.Nodes[0].UpdatedAt = first.Nodes[0].UpdatedAt
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(first)
	if !bytes.Equal(a, b) {
		t.Fatal("rollback not lossless")
	}
}
func TestUnknownStateSchemaIsNotSilentlyOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if e := os.WriteFile(p, []byte(`{"schema":999,"core_version":"1.14.0","nodes":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := ReadState(p)
	if e == nil || !strings.Contains(e.Error(), "999") {
		t.Fatal("unknown schema accepted")
	}
}
