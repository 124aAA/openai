package node

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"path"
	"strings"
)

// Storage compatibility is independently implemented from the fixed layout:
// CertMagic 60d9d8b415d6 account.go (CA/email keys), acmeissuer.go (issuer key),
// storage.go (safe components and certificate paths), Apache-2.0; sing-box
// v1.14.0/v1.14.3 service/acme/service.go fixes provider aliases. No ACME client
// implementation is copied or embedded. Unknown files remain recovery assets.
func migrationACMEPaths(r CertificateResource) (certificate, key, account, accountKey string) {
	ca := "https://acme-v02.api.letsencrypt.org/directory"
	if r.Certificate.ACME != nil {
		switch p := r.Certificate.ACME.Provider; p {
		case "", "letsencrypt":
		case "zerossl":
			ca = "https://acme.zerossl.com/v2/DV90"
		default:
			ca = p
		}
	}
	u, e := url.Parse(ca)
	issuer := ca
	if e == nil {
		issuer = u.Host
		if p := strings.Trim(strings.NewReplacer("/", "-", "\\", "-").Replace(u.Path), "-"); p != "" {
			issuer += "-" + p
		}
	}
	issuer = migrationACMESafe(issuer)
	prefix := ""
	if !r.LegacyStorage && r.Certificate.ACME != nil {
		prefix = path.Join("resources", r.ID)
	}
	domain := migrationACMESafe(r.Certificate.ServerName)
	certStem := path.Join(prefix, "certificates", issuer, domain, domain)
	email := strings.TrimSpace(strings.ToLower(r.Certificate.Email))
	userPart := email
	if at := strings.IndexByte(email, '@'); at >= 0 {
		if at == 0 {
			userPart = email[1:]
		} else {
			userPart = email[:at]
		}
	}
	if userPart == "" {
		userPart = "registration"
	}
	accountDir := path.Join(prefix, "acme", issuer, "users", migrationACMESafe(email))
	return certStem + ".crt", certStem + ".key", path.Join(accountDir, migrationACMESafe(userPart)+".json"), path.Join(accountDir, migrationACMESafe(userPart)+".key")
}

func migrationACMESafe(value string) string {
	value = strings.NewReplacer(" ", "_", "+", "_plus_", "*", "wildcard_", ":", "-", "..", "").Replace(strings.TrimSpace(strings.ToLower(value)))
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '@' || r == '.' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validMigrationACMEAccount(data []byte, email string) bool {
	// Preserve all original provider metadata bytes; inspect only identity and
	// required registration structure. This is not an online validity claim.
	if len(data) > MaxMigrationFileBytes || rejectSnapshotEnvelopeDuplicates(data) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	var status, location string
	var contacts []string
	if json.Unmarshal(fields["status"], &status) != nil || status != "valid" && status != "deactivated" && status != "revoked" || json.Unmarshal(fields["location"], &location) != nil || json.Unmarshal(fields["contact"], &contacts) != nil {
		return false
	}
	u, e := url.Parse(location)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	for _, contact := range contacts {
		scheme, address, ok := strings.Cut(contact, ":")
		if ok && strings.EqualFold(scheme, "mailto") && strings.EqualFold(address, strings.TrimSpace(email)) {
			return true
		}
	}
	return false
}

func validMigrationACMEAccountKey(data []byte) bool {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	if k, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		_, ok := k.(crypto.Signer)
		return ok
	}
	if _, e := x509.ParseECPrivateKey(block.Bytes); e == nil {
		return true
	}
	_, e := x509.ParsePKCS1PrivateKey(block.Bytes)
	return e == nil
}
