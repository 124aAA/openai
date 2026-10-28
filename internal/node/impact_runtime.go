package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"qingnode/internal/platform"
)

// RuntimeIdentityBackend supplies read-only evidence of inputs outside State.
// Identity is saved per generation, so replacing a core at the same version or
// changing the service invocation cannot silently use the metadata-only path.
type RuntimeIdentityBackend interface {
	RuntimeIdentity(State) ([]byte, error)
}

func (b SystemBackend) RuntimeIdentity(st State) ([]byte, error) {
	p := CorePath(b.Root, st.CoreVersion)
	coreHash := "missing"
	f, err := os.Open(p)
	if err == nil {
		h := sha256.New()
		_, err = io.Copy(h, f)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		coreHash = hex.EncodeToString(h.Sum(nil))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// This records the managed unit file, not a claim about loaded systemd
	// properties or arbitrary administrator drop-ins. Unit installation remains
	// a separate operation; metadata edits never rewrite it or daemon-reload.
	kind := b.ServiceManager().ResolvedKind()
	if kind == platform.InitUnavailable {
		kind = platform.InitSystemd
	} // embedded evidence only; never enables service control
	definition, err := ServiceDefinition(kind)
	if err != nil {
		return nil, err
	}
	unit := []byte(definition)
	unitSource := "embedded"
	manager := b.ServiceManager()
	manager.Kind = kind
	path, err := manager.DefinitionPath("qingnode")
	if err != nil {
		return nil, err
	}
	if actual, err := os.ReadFile(path); err == nil {
		unit, unitSource = actual, "managed-file"
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	h := sha256.Sum256(unit)
	certificateFiles, err := CertificateFileIdentities(st)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Format           int                       `json:"format"`
		CorePath         string                    `json:"core_path"`
		CoreSHA256       string                    `json:"core_sha256"`
		Service          string                    `json:"service"`
		ServiceSource    string                    `json:"service_source"`
		ServiceSHA256    string                    `json:"service_sha256"`
		ServeArguments   []string                  `json:"serve_arguments"`
		CertificateFiles []CertificateFileIdentity `json:"certificate_files,omitempty"`
	}{1, p, coreHash, map[platform.InitKind]string{platform.InitSystemd: "qingnode.service", platform.InitOpenRC: "openrc:qingnode"}[kind], unitSource, hex.EncodeToString(h[:]), []string{"run", "-c", "<generation>/server.json"}, certificateFiles})
}
