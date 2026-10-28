//go:build linux

package subscription

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func publicationDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "publication")
	if err := Initialize(dir, -1); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAtomicPrivatePublication(t *testing.T) {
	dir := publicationDir(t)
	s, raw := fixture()
	if err := Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(dir, -1); err != nil {
		t.Fatal("idempotent ownership", err)
	}
	for _, name := range []string{MarkerName, SnapshotName} {
		i, err := os.Stat(filepath.Join(dir, name))
		if err != nil || i.Mode().Perm() != 0640 {
			t.Fatal(name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, SnapshotName)); bytes.Contains(b, []byte(raw)) {
		t.Fatal("raw subscription token stored")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 80; j++ {
				read, err := Read(dir)
				if err != nil {
					errs <- err
					return
				}
				p := read.Records[0].Outputs["uri"].Content
				if !bytes.Equal(p, []byte("ss://private-device-a\n")) && !bytes.Equal(p, []byte("ss://private-device-b\n")) {
					t.Error("partial or mixed publication observed")
					return
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		p := s.Records[0].Outputs["uri"]
		if i%2 == 0 {
			p.Content = []byte("ss://private-device-b\n")
		} else {
			p.Content = []byte("ss://private-device-a\n")
		}
		s.Records[0].Outputs["uri"] = p
		if err := Publish(dir, s, -1); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, SnapshotName))
	if err != nil {
		t.Fatal(err)
	}
	s.Version = 99
	if err = Publish(dir, s, -1); err == nil {
		t.Fatal("invalid publication accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, SnapshotName))
	if !bytes.Equal(before, after) {
		t.Fatal("failed update replaced publication")
	}
	// A truncated private candidate has no effect because only snapshot.json is read.
	if err = os.WriteFile(filepath.Join(dir, ".publication-interrupted"), []byte(`{"version":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Read(dir); err != nil {
		t.Fatal("uncommitted candidate affected reader", err)
	}
	// Deliberate corruption of the committed snapshot fails closed, not from cache.
	if err = os.WriteFile(filepath.Join(dir, SnapshotName), []byte(`{"version":`), 0640); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(func() (Snapshot, error) { return Read(dir) }, HandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+raw+"/uri", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), raw) {
		t.Fatal("broken publication served stale or leaked", w.Code)
	}
}

func TestOpenedOldPublicationSurvivesAtomicReplacement(t *testing.T) {
	dir := publicationDir(t)
	s, _ := fixture()
	if err := Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	r, i, err := openDirectory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := r.OpenFile(SnapshotName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s.Records[0].Revoked = true
	if err = Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	old, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	_, _, links, err := owner(old)
	if err != nil || links != 0 {
		t.Fatalf("old descriptor was not unlinked: links=%d err=%v", links, err)
	}
	b, err := readOpenedFile(f, i, MaxSnapshotBytes)
	if err != nil {
		t.Fatal("valid opened old snapshot refused", err)
	}
	previous, err := Decode(b)
	if err != nil || previous.Records[0].Revoked {
		t.Fatal("old snapshot read was mixed", err)
	}
	current, err := Read(dir)
	if err != nil || !current.Records[0].Revoked {
		t.Fatal("a new read did not observe revocation", err)
	}
}

func TestInitializeAuditsExistingSnapshotWithoutRepair(t *testing.T) {
	dir := publicationDir(t)
	if err := Initialize(dir, -1); err != nil {
		t.Fatal("marked initial empty publication must remain usable", err)
	}
	s, _ := fixture()
	encoded, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte(`{"version":`), bytes.Replace(encoded, []byte(`"version": 1`), []byte(`"version": 2`), 1)} {
		if err = os.WriteFile(filepath.Join(dir, SnapshotName), bad, 0640); err != nil {
			t.Fatal(err)
		}
		if err = Initialize(dir, -1); err == nil {
			t.Fatal("initialization adopted an invalid committed publication")
		}
		actual, err := os.ReadFile(filepath.Join(dir, SnapshotName))
		if err != nil || !bytes.Equal(actual, bad) {
			t.Fatal("initialization repaired or rewrote invalid evidence", err)
		}
	}
	if err = Publish(dir, s, -1); err != nil {
		t.Fatal("explicit valid publication could not repair damaged JSON", err)
	}
	if err = Initialize(dir, -1); err != nil {
		t.Fatal("valid existing snapshot rejected", err)
	}
}

func TestPublicationPathAndPermissionGuards(t *testing.T) {
	for _, kind := range []string{"unmarked", "worldread", "groupwrite", "symlink", "hardlink", "fifo", "wrongmarker", "symlinkancestor", "writableancestor"} {
		t.Run(kind, func(t *testing.T) {
			dir := publicationDir(t)
			s, _ := fixture()
			if err := Publish(dir, s, -1); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, SnapshotName)
			switch kind {
			case "unmarked":
				if err := os.Remove(filepath.Join(dir, MarkerName)); err != nil {
					t.Fatal(err)
				}
			case "worldread":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "groupwrite":
				if err := os.Chmod(dir, 0770); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(p, p+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(SnapshotName+".saved", p); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p, p+".link"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(p, 0640); err != nil {
					t.Fatal(err)
				}
			case "wrongmarker":
				if err := os.WriteFile(filepath.Join(dir, MarkerName), []byte("someone else\n"), 0640); err != nil {
					t.Fatal(err)
				}
			case "symlinkancestor":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(filepath.Dir(dir), alias); err != nil {
					t.Fatal(err)
				}
				dir = filepath.Join(alias, filepath.Base(dir))
			case "writableancestor":
				if err := os.Chmod(filepath.Dir(dir), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Read(dir); err == nil {
				t.Fatal("unsafe read allowed")
			}
			if err := Publish(dir, s, -1); err == nil {
				t.Fatal("unsafe write allowed")
			}
			if err := Initialize(dir, -1); err == nil {
				t.Fatal("unsafe directory adopted")
			}
		})
	}
	base := t.TempDir()
	dir := filepath.Join(base, "foreign")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("other application"), 0600); err != nil {
		t.Fatal(err)
	}
	if Initialize(dir, -1) == nil {
		t.Fatal("foreign nonempty directory adopted")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "keep"))
	if string(b) != "other application" {
		t.Fatal("foreign file modified")
	}
	if _, err := os.Stat(filepath.Join(dir, MarkerName)); !os.IsNotExist(err) {
		t.Fatal("foreign marker written")
	}
}

func TestHTTPAtomicRotation(t *testing.T) {
	dir := publicationDir(t)
	s, old := fixture()
	now := s.GeneratedAt
	if err := Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(func() (Snapshot, error) { return Read(dir) }, HandlerOptions{Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	get := func(token string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+token+"/uri", nil))
		return w.Code
	}
	if get(old) != 200 {
		t.Fatal("initial authorization")
	}
	fresh, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	s.Records[0].Revoked = true
	next := s.Records[0]
	next.Revoked = false
	next.TokenID = "0000000000000001"
	next.TokenSHA256 = hash
	s.Records = append(s.Records, next)
	if err = Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	if get(old) != 404 || get(fresh) != 200 {
		t.Fatal("rotation did not revoke old token immediately")
	}
	s.Records[1].Revoked = true
	s.Records[1].Outputs = map[string]Payload{}
	if err = Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	if get(fresh) != 404 {
		t.Fatal("revocation served cached payload")
	}
}

func makeTLSFiles(t *testing.T, dir string, expired bool) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	notAfter := now.Add(time.Hour)
	if expired {
		notAfter = now.Add(-time.Minute)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(cp, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(kp, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cp, kp, pool
}

func TestServeTLSAndGracefulCancellation(t *testing.T) {
	dir := publicationDir(t)
	s, raw := fixture()
	now := time.Now().UTC()
	s.GeneratedAt = now
	s.Records[0].IssuedAt = now.Add(-time.Minute)
	s.Records[0].ExpiresAt = now.Add(time.Hour)
	if err := Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	cert, key, pool := makeTLSFiles(t, t.TempDir(), false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, ServeOptions{Directory: dir, PublicURL: "https://localhost", TLSCertFile: cert, TLSKeyFile: key})
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + ln.Addr().String() + "/s/" + raw + "/uri")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(b) != "ss://private-device-a\n" {
		t.Fatal("real verified TLS response", resp.StatusCode, err)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not terminate after cancellation")
	}
	if conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("owned listener remained open")
	}
	if _, err = Read(dir); err != nil {
		t.Fatal("server modified publication", err)
	}
}

func TestServeRejectsUnsafeDeployment(t *testing.T) {
	dir := publicationDir(t)
	s, _ := fixture()
	if err := Publish(dir, s, -1); err != nil {
		t.Fatal(err)
	}
	cert, key, _ := makeTLSFiles(t, t.TempDir(), false)
	expired, expiredKey, _ := makeTLSFiles(t, t.TempDir(), true)
	for name, opts := range map[string]ServeOptions{
		"plain":          {Directory: dir, PublicURL: "https://localhost"},
		"non https":      {Directory: dir, PublicURL: "http://localhost", ReverseProxy: true},
		"query":          {Directory: dir, PublicURL: "https://localhost?secret=token", ReverseProxy: true},
		"empty query":    {Directory: dir, PublicURL: "https://localhost?", ReverseProxy: true},
		"encoded slash":  {Directory: dir, PublicURL: "https://localhost/%2f", ReverseProxy: true},
		"wrong hostname": {Directory: dir, PublicURL: "https://other.invalid", TLSCertFile: cert, TLSKeyFile: key},
		"expired":        {Directory: dir, PublicURL: "https://localhost", TLSCertFile: expired, TLSKeyFile: expiredKey},
		"key mismatch":   {Directory: dir, PublicURL: "https://localhost", TLSCertFile: cert, TLSKeyFile: expiredKey},
		"both modes":     {Directory: dir, PublicURL: "https://localhost", TLSCertFile: cert, TLSKeyFile: key, ReverseProxy: true},
	} {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			if err = Serve(context.Background(), ln, opts); err == nil {
				t.Fatal("unsafe server deployment allowed")
			}
			if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
				c.Close()
				t.Fatal("rejected deployment leaked listener")
			}
		})
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = Serve(context.Background(), ln, ServeOptions{Directory: dir, PublicURL: "https://localhost", ReverseProxy: true}); err == nil {
		t.Fatal("public HTTP listener allowed")
	}
}

func TestDedicatedReaderCannotPublish(t *testing.T) {
	if os.Getenv("QINGNODE_SUBSCRIPTION_READER_FIXTURE") == "1" {
		dir := os.Getenv("QINGNODE_SUBSCRIPTION_READER_DIR")
		s, err := Read(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Records) != 1 {
			t.Fatal("missing publication")
		}
		if err = Publish(dir, s, -1); err == nil {
			t.Fatal("reader can publish root-owned data")
		}
		if err = os.WriteFile(filepath.Join(dir, SnapshotName), []byte("changed"), 0640); err == nil {
			t.Fatal("reader can modify publication")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- Serve(ctx, ln, ServeOptions{Directory: dir, PublicURL: "https://localhost", ReverseProxy: true})
		}()
		_, raw := fixture()
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://" + ln.Addr().String() + "/s/" + raw + "/uri")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal("unprivileged service response", resp.StatusCode)
		}
		cancel()
		select {
		case err = <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("unprivileged server did not stop")
		}
		client.CloseIdleConnections()
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root only to launch a dedicated uid/gid 65534 reader; ordinary read/write tests still run")
	}
	// Keep the entire fixture under one new directory. t.TempDir's returned
	// 001 directory has a second, private 0700 parent, which a service UID
	// cannot traverse even if 001 itself is group-readable.
	base, err := os.MkdirTemp("", "qingnode-subscription-reader-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(base, 0, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0750); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "publication")
	if err := Initialize(dir, 65534); err != nil {
		t.Fatal(err)
	}
	s, _ := fixture()
	s.GeneratedAt = time.Now().UTC()
	s.Records[0].IssuedAt = s.GeneratedAt.Add(-time.Minute)
	s.Records[0].ExpiresAt = s.GeneratedAt.Add(time.Hour)
	if err := Publish(dir, s, 65534); err != nil {
		t.Fatal(err)
	}
	// go test's build directory can be 0700; copy this test executable into the
	// owned, group-traversable fixture rather than widening Go's private tree.
	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	executable := filepath.Join(base, "reader-test")
	dst, err := os.OpenFile(executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0750)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(dst, src); err == nil {
		err = dst.Chown(0, 65534)
	}
	if err == nil {
		err = dst.Chmod(0750)
	}
	ce := dst.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestDedicatedReaderCannotPublish$", "-test.v")
	cmd.Env = append(os.Environ(), "QINGNODE_SUBSCRIPTION_READER_FIXTURE=1", "QINGNODE_SUBSCRIPTION_READER_DIR="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{65534}}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dedicated uid/gid reader: %v\n%s", err, out)
	}
	t.Log("dedicated uid/gid 65534 read and authenticated HTTP service succeeded; publish and direct writes refused")
}
