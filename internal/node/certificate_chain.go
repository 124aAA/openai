package node

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

// This stronger path is deliberately limited to explicit resource import and
// update. Reading legacy State, inspecting recovery material and date checks
// must not depend on the current host's trust store or require online access.
func validateCertificateImportChain(r CertificateResource, now time.Time) error {
	if r.Certificate.Mode == "acme" {
		return nil
	}
	certificate, key, err := certificateMaterial(r.Certificate)
	if err != nil {
		return err
	}
	leaf, chain, err := parseCertificateChain(certificate, key)
	if err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		// An explicitly included private root can still form a complete path.
		roots = x509.NewCertPool()
	}
	return verifyCertificateImportChain(leaf, chain, r.Certificate.ServerName, now, roots)
}

func verifyCertificateImportChain(leaf *x509.Certificate, chain []*x509.Certificate, name string, now time.Time, trustedRoots *x509.CertPool) error {
	if leaf == nil || len(chain) == 0 {
		return errors.New("证书链为空")
	}
	roots := x509.NewCertPool()
	if trustedRoots != nil {
		roots = trustedRoots.Clone()
	}
	last := chain[len(chain)-1]
	if bytes.Equal(last.RawIssuer, last.RawSubject) {
		if last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature) != nil {
			return errors.New("显式附带的私有根签名无效")
		}
		roots.AddCert(last)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("证书链无法连接到本机受信任根或明确附带的自签根；请补齐中间证书及必要私有根。通过校验不代表其它客户端已信任该CA")
	}
	return nil
}
