package node

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CertificateResource is the sole persisted owner of certificate material.
// Node.Certificate is a resolved in-memory compatibility projection only.
type CertificateResource struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Certificate   Certificate `json:"certificate"`
	LegacyStorage bool        `json:"legacy_storage,omitempty"`
}
type ACMESettings struct {
	Challenge           string     `json:"challenge"`
	Provider            string     `json:"provider,omitempty"`
	KeyType             string     `json:"key_type,omitempty"`
	AlternativeHTTPPort int        `json:"alternative_http_port,omitempty"`
	AlternativeTLSPort  int        `json:"alternative_tls_port,omitempty"`
	DNS01               *ACMEDNS01 `json:"dns01,omitempty"`
}
type ACMEDNS01 struct {
	Provider           string   `json:"provider"`
	TTL                string   `json:"ttl,omitempty"`
	PropagationDelay   string   `json:"propagation_delay,omitempty"`
	PropagationTimeout string   `json:"propagation_timeout,omitempty"`
	Resolvers          []string `json:"resolvers,omitempty"`
	OverrideDomain     string   `json:"override_domain,omitempty"`
	AccessKeyID        string   `json:"access_key_id,omitempty"`
	AccessKeySecret    string   `json:"access_key_secret,omitempty"`
	RegionID           string   `json:"region_id,omitempty"`
	SecurityToken      string   `json:"security_token,omitempty"`
	APIToken           string   `json:"api_token,omitempty"`
	ZoneToken          string   `json:"zone_token,omitempty"`
	Username           string   `json:"username,omitempty"`
	Password           string   `json:"password,omitempty"`
	Subdomain          string   `json:"subdomain,omitempty"`
	ServerURL          string   `json:"server_url,omitempty"`
}

func (s *State) FindCertificate(id string) (*CertificateResource, error) {
	for i := range s.Certificates {
		if s.Certificates[i].ID == id {
			return &s.Certificates[i], nil
		}
	}
	for i := range s.Certificates {
		if s.Certificates[i].Name == id {
			return &s.Certificates[i], nil
		}
	}
	return nil, errors.New("证书资源不存在")
}
func CertificateReferences(s State, id string) []string {
	var result []string
	for _, n := range s.Nodes {
		if n.CertificateID == id {
			result = append(result, n.ID)
		}
	}
	sort.Strings(result)
	return result
}

// ResolveCertificates never reads or changes the filesystem.
func ResolveCertificates(s *State) error {
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.CertificateID == "" {
			continue
		}
		r, err := s.FindCertificate(n.CertificateID)
		if err != nil || r.ID != n.CertificateID {
			return errors.New("节点引用的证书资源不存在")
		}
		n.Certificate = cloneCertificate(r.Certificate)
	}
	return nil
}
func cloneCertificate(c Certificate) *Certificate {
	data, _ := json.Marshal(c)
	var copy Certificate
	_ = json.Unmarshal(data, &copy)
	return &copy
}
func certificateID(c Certificate, legacy bool) string {
	b, _ := json.Marshal(struct {
		Certificate Certificate
		Legacy      bool
	}{c, legacy})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// CanonicalCertificates adapts old caller fixtures and legacy node edits. A
// replacement projection is copy-on-write, so editing one node never rotates a
// certificate used by another node. Explicit resource updates are separate.
func CanonicalCertificates(s State) (State, error) {
	if s.Nodes != nil {
		s.Nodes = append([]Node{}, s.Nodes...)
	}
	if s.Certificates != nil {
		s.Certificates = append([]CertificateResource{}, s.Certificates...)
		for i := range s.Certificates {
			s.Certificates[i].Certificate = *cloneCertificate(s.Certificates[i].Certificate)
		}
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		var current *CertificateResource
		if n.CertificateID != "" {
			for j := range s.Certificates {
				if s.Certificates[j].ID == n.CertificateID {
					current = &s.Certificates[j]
					break
				}
			}
			if current == nil {
				return State{}, errors.New("节点引用的证书资源不存在")
			}
		}
		if n.Certificate != nil && (current == nil || !equalJSON(*n.Certificate, current.Certificate)) {
			legacy := n.Certificate.Mode == "acme" && (n.Certificate.ACME == nil || current != nil && current.LegacyStorage)
			id := certificateID(*n.Certificate, legacy)
			found := false
			for _, r := range s.Certificates {
				if r.ID == id {
					if !equalJSON(r.Certificate, *n.Certificate) || r.LegacyStorage != legacy {
						return State{}, errors.New("证书资源身份冲突")
					}
					found = true
				}
			}
			if !found {
				s.Certificates = append(s.Certificates, CertificateResource{ID: id, Name: "certificate-" + id, Certificate: *cloneCertificate(*n.Certificate), LegacyStorage: legacy})
			}
			n.CertificateID = id
		}
	}
	if err := ResolveCertificates(&s); err != nil {
		return State{}, err
	}
	return s, nil
}

// State serialization writes one certificate copy per resource. This also
// makes existing constructors using inline certificates safe to persist.
func (s State) MarshalJSON() ([]byte, error) {
	type wire State
	if s.Schema >= 6 {
		var err error
		s, err = CanonicalCertificates(s)
		if err != nil {
			return nil, err
		}
		for i := range s.Nodes {
			s.Nodes[i].Certificate = nil
		}
	}
	return json.Marshal(wire(s))
}
func (s *State) UnmarshalJSON(data []byte) error {
	type wire State
	var value wire
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("状态含多余数据")
	}
	*s = State(value)
	return ResolveCertificates(s)
}

func validateCertificateResources(s State, deferExternalFiles bool) error {
	if len(s.Certificates) > 256 {
		return errors.New("证书资源超过256项上限")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, r := range s.Certificates {
		if !idRE.MatchString(r.ID) || ids[r.ID] || !cleanName(r.Name) || names[r.Name] {
			return errors.New("证书资源ID或名称无效或重复")
		}
		ids[r.ID] = true
		names[r.Name] = true
		if r.LegacyStorage && r.Certificate.Mode != "acme" {
			return errors.New("旧ACME存储标记不能用于新证书模式")
		}
		if r.Certificate.Mode == "acme" && r.Certificate.ACME == nil && !r.LegacyStorage {
			return errors.New("ACME资源缺少明确挑战设置或旧存储声明")
		}
		if err := validateCertificateResource(r, time.Now(), false, !deferExternalFiles); err != nil {
			return fmt.Errorf("证书资源 %s：%w", r.ID, err)
		}
	}
	for _, n := range s.Nodes {
		if n.CertificateID != "" && !ProtocolRequiresCertificate(n.Protocol) {
			return errors.New("该协议不使用TLS证书资源")
		}
	}
	for _, challenge := range CertificateChallengeBindings(s) {
		for _, binding := range StateBindings(s) {
			if bindingTransport(binding.Network) == "tcp" && binding.Port == challenge.Port {
				return errors.New("ACME本地挑战端口与受管TCP监听冲突；请选择独立端口并配置公网80/443转发，或使用DNS-01")
			}
		}
	}
	return nil
}

func certificateMaterial(c Certificate) ([]byte, []byte, error) {
	if c.Mode == "pem" {
		return []byte(c.CertPEM), []byte(c.KeyPEM), nil
	}
	if c.Mode != "file" {
		return nil, nil, errors.New("该证书模式没有静态PEM")
	}
	cert, err := readCertificateFile(c.CertificatePath, false)
	if err != nil {
		return nil, nil, err
	}
	key, err := readCertificateFile(c.KeyPath, true)
	return cert, key, err
}
func readCertificateFile(path string, private bool) ([]byte, error) {
	data, _, err := readCertificateFileStat(path, private)
	return data, err
}
func readCertificateFileStat(path string, private bool) ([]byte, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, errors.New("证书文件引用须为规范绝对路径")
	}
	// Reject every symlink component, including user-controlled ancestors.
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return nil, nil, errors.New("证书引用文件不可访问")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("证书引用不接受符号链接")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	f, err := openCertificateReference(path)
	if err != nil {
		return nil, nil, errors.New("证书引用文件不可读或路径已改变")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, nil, errors.New("证书引用须为不超过1MiB的普通文件")
	}
	if _, _, err := certificateFileOwner(st); err != nil {
		return nil, nil, err
	}
	if st.Mode().Perm()&0022 != 0 || private && st.Mode().Perm()&0007 != 0 {
		return nil, nil, errors.New("证书引用权限过宽；私钥不能向其他用户开放")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, nil, errors.New("证书引用读取失败或超限")
	}
	return b, st, nil
}
func parseCertificateChain(certPEM, keyPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certPEM, keyPEM = bytes.TrimSpace(certPEM), bytes.TrimSpace(keyPEM)
	if len(certPEM) > 1<<20 || len(keyPEM) > 1<<20 {
		return nil, nil, errors.New("证书或私钥超过1MiB")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, errors.New("证书与私钥不匹配或PEM无效")
	}
	rest := certPEM
	var chain []*x509.Certificate
	for len(bytes.TrimSpace(rest)) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("证书链含非证书或无效PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, errors.New("证书链无法解析")
		}
		chain = append(chain, c)
		rest = next
	}
	if len(chain) == 0 || len(chain) > 16 || len(pair.Certificate) != len(chain) {
		return nil, nil, errors.New("证书链为空或超过16项")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, nil, errors.New("证书链顺序、签名或CA约束无效")
		}
	}
	last := chain[len(chain)-1]
	if len(chain) == 1 && !bytes.Equal(last.RawIssuer, last.RawSubject) {
		return nil, nil, errors.New("缺少中间证书：请导入完整证书链")
	}
	if bytes.Equal(last.RawIssuer, last.RawSubject) && last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature) != nil {
		return nil, nil, errors.New("自签证书签名无效")
	}
	return chain[0], chain, nil
}
func ValidateCertificateResource(r CertificateResource, now time.Time, checkDates bool) error {
	return validateCertificateResource(r, now, checkDates, true)
}
func validateCertificateResource(r CertificateResource, now time.Time, checkDates, checkExternalFiles bool) error {
	c := r.Certificate
	if !ValidHost(c.ServerName) {
		return errors.New("证书名称无效")
	}
	switch c.Mode {
	case "pem", "file":
		if c.Email != "" || c.ACME != nil {
			return errors.New("静态证书不能包含ACME设置")
		}
		if c.Mode == "pem" && (c.CertificatePath != "" || c.KeyPath != "") || c.Mode == "file" && (c.CertPEM != "" || c.KeyPEM != "") {
			return errors.New("PEM内容与外部文件引用不能混用")
		}
		if c.Mode == "file" {
			for _, path := range []string{c.CertificatePath, c.KeyPath} {
				if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
					return errors.New("证书文件引用须为规范绝对路径")
				}
			}
			if !checkExternalFiles {
				return nil
			}
		}
		cert, key, err := certificateMaterial(c)
		if err != nil {
			return err
		}
		leaf, chain, err := parseCertificateChain(cert, key)
		if err != nil {
			return err
		}
		if err = leaf.VerifyHostname(c.ServerName); err != nil {
			return errors.New("证书SAN不包含指定名称")
		}
		if leaf.PublicKeyAlgorithm != x509.ECDSA && leaf.PublicKeyAlgorithm != x509.RSA && leaf.PublicKeyAlgorithm != x509.Ed25519 {
			return errors.New("证书公钥算法须为ECDSA、RSA或Ed25519；客户端兼容性需单独验证")
		}
		if key, ok := leaf.PublicKey.(*rsa.PublicKey); ok && key.N.BitLen() < 2048 {
			return errors.New("RSA证书密钥至少2048位")
		}
		if len(leaf.ExtKeyUsage) > 0 {
			serverAuth := false
			for _, usage := range leaf.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
					serverAuth = true
				}
			}
			if !serverAuth {
				return errors.New("证书用途不允许TLS服务器认证")
			}
		}
		if checkDates {
			for _, item := range chain {
				if now.Before(item.NotBefore) || !now.Before(item.NotAfter) {
					return errors.New("证书链尚未生效或已过期；旧有效证书未被替换")
				}
			}
		}
	case "acme":
		if c.CertPEM != "" || c.KeyPEM != "" || c.CertificatePath != "" || c.KeyPath != "" {
			return errors.New("ACME不能混入静态证书")
		}
		if net.ParseIP(c.ServerName) != nil || !strings.Contains(c.Email, "@") || strings.ContainsAny(c.Email, "\x00\r\n") {
			return errors.New("ACME需要域名与有效邮箱")
		}
		if c.ACME != nil {
			return validateACME(*c.ACME)
		}
	default:
		return errors.New("证书模式须为pem、file或acme")
	}
	return nil
}
func validateACME(a ACMESettings) error {
	switch a.Challenge {
	case "http-01", "tls-alpn-01", "dns-01":
	default:
		return errors.New("ACME挑战须为http-01、dns-01或tls-alpn-01")
	}
	if a.Provider != "" && a.Provider != "letsencrypt" && a.Provider != "zerossl" {
		u, e := url.Parse(a.Provider)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
			return errors.New("自定义CA须为不含凭据的HTTPS目录地址")
		}
	}
	switch a.KeyType {
	case "", "p256", "p384", "rsa2048", "rsa4096":
	default:
		return errors.New("HY2 ACME证书算法仅支持p256/p384/rsa2048/rsa4096")
	}
	for _, p := range []int{a.AlternativeHTTPPort, a.AlternativeTLSPort} {
		if p < 0 || p > 65535 {
			return errors.New("ACME本地替代端口无效")
		}
	}
	if a.Challenge != "http-01" && a.AlternativeHTTPPort != 0 || a.Challenge != "tls-alpn-01" && a.AlternativeTLSPort != 0 {
		return errors.New("替代端口与ACME挑战类型不符")
	}
	if a.Challenge != "dns-01" {
		if a.DNS01 != nil {
			return errors.New("非DNS挑战不能包含DNS凭据")
		}
		return nil
	}
	if a.DNS01 == nil {
		return errors.New("DNS-01缺少提供者设置")
	}
	d := a.DNS01
	validSecret := func(v string) bool { return len(v) > 0 && len(v) <= 4096 && !strings.ContainsAny(v, "\x00\r\n") }
	switch d.Provider {
	case "alidns":
		if !validSecret(d.AccessKeyID) || !validSecret(d.AccessKeySecret) || !validSecret(d.RegionID) || d.APIToken != "" || d.ZoneToken != "" || d.Username != "" || d.Password != "" || d.Subdomain != "" || d.ServerURL != "" {
			return errors.New("alidns需要access_key_id/access_key_secret/region_id且不能混用提供者字段")
		}
	case "cloudflare":
		if !validSecret(d.APIToken) || d.AccessKeyID != "" || d.AccessKeySecret != "" || d.RegionID != "" || d.SecurityToken != "" || d.Username != "" || d.Password != "" || d.Subdomain != "" || d.ServerURL != "" {
			return errors.New("cloudflare需要api_token且不能混用提供者字段")
		}
	case "acmedns":
		u, e := url.Parse(d.ServerURL)
		if !validSecret(d.Username) || !validSecret(d.Password) || !validSecret(d.Subdomain) || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || d.AccessKeyID != "" || d.AccessKeySecret != "" || d.RegionID != "" || d.SecurityToken != "" || d.APIToken != "" || d.ZoneToken != "" {
			return errors.New("acmedns需要username/password/subdomain/HTTPS server_url且不能混用提供者字段")
		}
	default:
		return errors.New("当前核心仅适配alidns、cloudflare、acmedns")
	}
	for _, v := range []string{d.SecurityToken, d.ZoneToken} {
		if v != "" && !validSecret(v) {
			return errors.New("DNS凭据格式无效")
		}
	}
	for _, item := range []struct {
		v        string
		min, max time.Duration
	}{{d.TTL, time.Second, 24 * time.Hour}, {d.PropagationDelay, 0, 10 * time.Minute}, {d.PropagationTimeout, time.Second, 30 * time.Minute}} {
		if item.v != "" {
			dur, e := time.ParseDuration(item.v)
			if e != nil || dur < item.min || dur > item.max {
				return errors.New("DNS TTL/传播等待超出范围；不允许关闭传播检查")
			}
		}
	}
	if d.PropagationDelay != "" && d.PropagationTimeout != "" {
		delay, _ := time.ParseDuration(d.PropagationDelay)
		timeout, _ := time.ParseDuration(d.PropagationTimeout)
		if delay >= timeout {
			return errors.New("传播延迟必须小于传播总超时")
		}
	}
	delegation := strings.TrimPrefix(d.OverrideDomain, "_acme-challenge.")
	if d.OverrideDomain != "" && (!domainRE.MatchString(delegation) || net.ParseIP(delegation) != nil) {
		return errors.New("DNS委派域名无效")
	}
	if len(d.Resolvers) > 4 {
		return errors.New("传播检查最多4个resolver")
	}
	for _, resolver := range d.Resolvers {
		host, port, e := net.SplitHostPort(resolver)
		if e != nil || net.ParseIP(host) == nil || port != "53" {
			return errors.New("传播resolver须为IP:53，IPv6使用方括号")
		}
	}
	return nil
}

func CertificateACMEDirectory(root string, r CertificateResource) string {
	if r.LegacyStorage || r.Certificate.Mode == "acme" && r.Certificate.ACME == nil {
		return filepath.Join(root, "acme")
	}
	return filepath.Join(root, "acme", "resources", r.ID)
}
func certificateACMEProvider(n Node, root string) M {
	c := n.Certificate
	r := CertificateResource{ID: n.CertificateID, Certificate: *c, LegacyStorage: c.ACME == nil}
	out := M{"type": "acme", "domain": []string{c.ServerName}, "email": c.Email, "data_directory": CertificateACMEDirectory(root, r), "disable_tls_alpn_challenge": true}
	if c.ACME == nil {
		return out
	}
	a := c.ACME
	if a.Provider != "" {
		out["provider"] = a.Provider
	}
	if a.KeyType != "" {
		out["key_type"] = a.KeyType
	}
	switch a.Challenge {
	case "http-01":
		if a.AlternativeHTTPPort != 0 {
			out["alternative_http_port"] = a.AlternativeHTTPPort
		}
	case "tls-alpn-01":
		out["disable_http_challenge"] = true
		out["disable_tls_alpn_challenge"] = false
		if a.AlternativeTLSPort != 0 {
			out["alternative_tls_port"] = a.AlternativeTLSPort
		}
	case "dns-01":
		out["disable_http_challenge"] = true
		out["disable_tls_alpn_challenge"] = true
		if a.DNS01 != nil {
			b, _ := json.Marshal(a.DNS01)
			var dns M
			_ = json.Unmarshal(b, &dns)
			out["dns01_challenge"] = dns
		}
	}
	return out
}

// CertificateChallengeBindings are local challenge listeners, never proof that
// the CA can reach public port 80/443. DNS-01 needs no inbound TCP port.
func CertificateChallengeBindings(s State) []LocalBinding {
	var result []LocalBinding
	seen := map[string]bool{}
	for _, n := range s.Nodes {
		if !n.Enabled || n.Certificate == nil || n.Certificate.Mode != "acme" {
			continue
		}
		c := n.Certificate
		port := 80
		if c.ACME != nil {
			switch c.ACME.Challenge {
			case "dns-01":
				continue
			case "http-01":
				if c.ACME.AlternativeHTTPPort != 0 {
					port = c.ACME.AlternativeHTTPPort
				}
			case "tls-alpn-01":
				port = 443
				if c.ACME.AlternativeTLSPort != 0 {
					port = c.ACME.AlternativeTLSPort
				}
			}
		}
		key := fmt.Sprint(port)
		if !seen[key] {
			result = append(result, LocalBinding{NodeID: "certificate-" + n.CertificateID, Network: "tcp", Address: "0.0.0.0", Port: port})
			seen[key] = true
		}
	}
	return result
}

type CertificateAsset struct {
	ResourceID string `json:"resource_id"`
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Managed    bool   `json:"managed"`
	Required   bool   `json:"required"`
}

func CertificateAssetInventory(s State, root string) ([]CertificateAsset, error) {
	s, e := CanonicalCertificates(s)
	if e != nil {
		return nil, e
	}
	var assets []CertificateAsset
	for _, r := range s.Certificates {
		switch r.Certificate.Mode {
		case "acme":
			assets = append(assets, CertificateAsset{r.ID, "acme-storage", CertificateACMEDirectory(root, r), true, true})
		case "file":
			assets = append(assets, CertificateAsset{r.ID, "certificate-file", r.Certificate.CertificatePath, false, true}, CertificateAsset{r.ID, "private-key-file", r.Certificate.KeyPath, false, true})
		}
	}
	return assets, nil
}

func PutCertificateResource(s State, r CertificateResource) (State, error) {
	r.Certificate = *cloneCertificate(r.Certificate)
	var e error
	s, e = CanonicalCertificates(s)
	if e != nil {
		return State{}, e
	}
	if r.ID == "" {
		r.ID = Token(8)
	}
	if r.Name == "" {
		r.Name = "certificate-" + r.ID
	}
	if r.Certificate.Mode == "acme" && r.Certificate.ACME == nil {
		r.LegacyStorage = true
	}
	if e = ValidateCertificateResource(r, time.Now(), true); e != nil {
		return State{}, e
	}
	if e = validateCertificateImportChain(r, time.Now()); e != nil {
		return State{}, e
	}
	found := false
	for i := range s.Certificates {
		if s.Certificates[i].ID == r.ID {
			s.Certificates[i] = r
			found = true
			break
		}
	}
	if !found {
		s.Certificates = append(s.Certificates, r)
	}
	if e = ResolveCertificates(&s); e != nil {
		return State{}, e
	}
	if e = s.Validate(); e != nil {
		return State{}, e
	}
	return s, nil
}
func RemoveCertificateResource(s State, id string) (State, error) {
	s, e := CanonicalCertificates(s)
	if e != nil {
		return State{}, e
	}
	r, e := s.FindCertificate(id)
	if e != nil {
		return State{}, e
	}
	if len(CertificateReferences(s, r.ID)) > 0 {
		return State{}, errors.New("证书仍被节点引用，请先解除或更换引用")
	}
	for i := range s.Certificates {
		if s.Certificates[i].ID == r.ID {
			s.Certificates = append(s.Certificates[:i], s.Certificates[i+1:]...)
			break
		}
	}
	return s, nil
}
func BindCertificate(s State, nodeID, certificateID string) (State, error) {
	s, e := CanonicalCertificates(s)
	if e != nil {
		return State{}, e
	}
	n, e := s.Find(nodeID)
	if e != nil {
		return State{}, e
	}
	if !ProtocolRequiresCertificate(n.Protocol) {
		return State{}, errors.New("该协议不使用TLS证书")
	}
	if certificateID == "" {
		if n.Enabled {
			return State{}, errors.New("启用的TLS节点不能解除证书引用")
		}
		n.CertificateID = ""
		n.Certificate = nil
		return s, nil
	}
	r, e := s.FindCertificate(certificateID)
	if e != nil {
		return State{}, e
	}
	n.CertificateID = r.ID
	n.Certificate = cloneCertificate(r.Certificate)
	if e = s.Validate(); e != nil {
		return State{}, e
	}
	return s, nil
}

type CertificateStatus struct {
	ResourceID    string     `json:"resource_id"`
	Status        string     `json:"status"`
	Mode          string     `json:"mode"`
	Algorithm     string     `json:"algorithm,omitempty"`
	SANs          []string   `json:"sans,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	DaysRemaining *int       `json:"days_remaining,omitempty"`
	Reason        string     `json:"reason,omitempty"`
	Storage       string     `json:"storage,omitempty"`
	Evidence      string     `json:"evidence"`
}

func InspectCertificateResource(r CertificateResource, root string, now time.Time) (CertificateStatus, error) {
	result := CertificateStatus{ResourceID: r.ID, Mode: r.Certificate.Mode, Status: "configured", Evidence: "configuration-only"}
	var leaf *x509.Certificate
	selectedValid := false
	selectedReason := ""
	if r.Certificate.Mode == "acme" {
		result.Storage = CertificateACMEDirectory(root, r)
		// The legacy root also contains newer resources, and a resource can
		// retain an older CA's cache after an explicit provider change. Only
		// the fixed issuer/domain paths used by this resource are evidence.
		certificateRelative, keyRelative, _, _ := migrationACMEPaths(r)
		certificatePath := filepath.Join(root, "acme", filepath.FromSlash(certificateRelative))
		keyPath := filepath.Join(root, "acme", filepath.FromSlash(keyRelative))
		metadataPath := strings.TrimSuffix(certificatePath, ".crt") + ".json"
		present := map[string]bool{}
		files, bytesRead := 0, int64(0)
		invalidCandidates := false
		err := filepath.WalkDir(result.Storage, func(path string, d os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) && path == result.Storage {
				return nil
			}
			if err != nil {
				return errors.New("ACME存储不可读取")
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("ACME存储包含符号链接")
			}
			if path == certificatePath || path == keyPath || path == metadataPath {
				present[path] = true
			}
			if d.IsDir() {
				return nil
			}
			files++
			if files > 512 {
				return errors.New("ACME状态扫描超过512文件上限")
			}
			info, e := d.Info()
			if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
				return errors.New("ACME状态存储条目异常")
			}
			if path != certificatePath {
				return nil
			}
			bytesRead += info.Size()
			if bytesRead > 8<<20 {
				return errors.New("ACME状态扫描超过8MiB")
			}
			data, e := readCertificateFile(path, false)
			if e != nil {
				return errors.New("ACME证书不可读取")
			}
			block, _ := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				invalidCandidates = true
				return nil
			}
			c, e := x509.ParseCertificate(block.Bytes)
			if e != nil || c.VerifyHostname(r.Certificate.ServerName) != nil {
				invalidCandidates = true
				return nil
			}
			key, e := readCertificateFile(keyPath, true)
			if e != nil {
				invalidCandidates = true
				return nil
			}
			metadata, e := readCertificateFile(metadataPath, false)
			var metadataFields map[string]json.RawMessage
			if e != nil || rejectSnapshotEnvelopeDuplicates(metadata) != nil || json.Unmarshal(metadata, &metadataFields) != nil || metadataFields == nil {
				invalidCandidates = true
				return nil
			}
			bytesRead += int64(len(metadata))
			if bytesRead > 8<<20 {
				return errors.New("ACME状态扫描超过8MiB")
			}
			bytesRead += int64(len(key))
			if bytesRead > 8<<20 {
				return errors.New("ACME状态扫描超过8MiB")
			}
			c, _, e = parseCertificateChain(data, key)
			if e != nil {
				invalidCandidates = true
				return nil
			}
			candidateErr := ValidateCertificateResource(CertificateResource{Certificate: Certificate{Mode: "pem", ServerName: r.Certificate.ServerName, CertPEM: string(data), KeyPEM: string(key)}}, now, true)
			valid := candidateErr == nil
			if !valid {
				invalidCandidates = true
			}
			if leaf == nil || valid && !selectedValid || valid == selectedValid && c.NotAfter.After(leaf.NotAfter) {
				leaf = c
				selectedValid = valid
				selectedReason = ""
				if candidateErr != nil {
					selectedReason = candidateErr.Error()
				}
			}
			return nil
		})
		if err != nil {
			result.Status = "failed"
			result.Reason = err.Error()
			return result, err
		}
		if leaf == nil {
			if invalidCandidates || len(present) > 0 {
				result.Status = "failed"
				result.Reason = "指定CA/域名的证书、配对私钥或元数据不完整或无效；未确认签发可用"
			}
			return result, nil
		}
		if invalidCandidates {
			result.Reason = "另有无法验证的候选证书；当前展示可配对证书，不代表运行核心已采用或最近签发成功"
		}
	} else {
		cert, key, err := certificateMaterial(r.Certificate)
		if err != nil {
			result.Status = "failed"
			result.Reason = err.Error()
			return result, err
		}
		leaf, _, err = parseCertificateChain(cert, key)
		if err != nil {
			result.Status = "failed"
			result.Reason = err.Error()
			return result, err
		}
		validationErr := ValidateCertificateResource(r, now, true)
		if validationErr != nil {
			selectedReason = validationErr.Error()
		}
	}
	result.Evidence = "certificate-file-observed; not issuance/renewal event history"
	result.Algorithm = leaf.PublicKeyAlgorithm.String()
	result.SANs = append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		result.SANs = append(result.SANs, ip.String())
	}
	result.NotBefore = &leaf.NotBefore
	result.NotAfter = &leaf.NotAfter
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	result.DaysRemaining = &days
	switch {
	case selectedReason != "":
		result.Status = "failed"
		result.Reason = selectedReason
	case now.Before(leaf.NotBefore):
		result.Status = "failed"
		result.Reason = "证书尚未生效"
	case !now.Before(leaf.NotAfter):
		result.Status = "failed"
		result.Reason = "证书已过期"
	case leaf.NotAfter.Sub(now) < 30*24*time.Hour:
		result.Status = "expiring"
	default:
		result.Status = "available"
	}
	return result, nil
}
