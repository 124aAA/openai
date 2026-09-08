package node

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"
)

const Schema = 1
const DefaultCore = "1.14.0"

type State struct {
	Schema            int    `json:"schema"`
	CoreVersion       string `json:"core_version"`
	Nodes             []Node `json:"nodes"`
	Firewall          string `json:"firewall,omitempty"`
	CoreArchiveSHA256 string `json:"core_archive_sha256,omitempty"`
}
type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}
type Reality struct {
	ServerName  string `json:"server_name"`
	Target      string `json:"target"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
type Certificate struct {
	Mode       string `json:"mode"`
	ServerName string `json:"server_name"`
	CertPEM    string `json:"certificate_pem,omitempty"`
	KeyPEM     string `json:"key_pem,omitempty"`
	Email      string `json:"email,omitempty"`
}
type Node struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Protocol    string       `json:"protocol"`
	Host        string       `json:"host"`
	Listen      string       `json:"listen"`
	Port        int          `json:"port"`
	Enabled     bool         `json:"enabled"`
	Users       []User       `json:"users"`
	Reality     *Reality     `json:"reality,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	Shadowsocks *Shadowsocks `json:"shadowsocks,omitempty"`
	CreatedAt   string       `json:"created_at,omitempty"`
	UpdatedAt   string       `json:"updated_at,omitempty"`
}

func Token(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func NewUser(name, protocol string) User {
	u := User{ID: Token(8), Name: name}
	if p, ok := Protocol(protocol); ok {
		p.Credential(&u)
	}
	return u
}
func NewReality(sni, target string) (*Reality, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if target == "" {
		target = net.JoinHostPort(sni, "443")
	}
	return &Reality{ServerName: sni, Target: target, PrivateKey: base64.RawURLEncoding.EncodeToString(k.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), ShortID: Token(8)}, nil
}
func NewState() State { return State{Schema: Schema, CoreVersion: DefaultCore, Nodes: []Node{}} }
func (s State) Clone() State {
	b, _ := json.Marshal(s)
	var c State
	_ = json.Unmarshal(b, &c)
	return c
}
func (s *State) Find(id string) (*Node, error) {
	for i := range s.Nodes {
		if s.Nodes[i].ID == id || s.Nodes[i].Name == id {
			return &s.Nodes[i], nil
		}
	}
	return nil, fmt.Errorf("节点不存在：%s", id)
}
func Network(n Node) string {
	nets := Networks(n)
	if len(nets) > 0 {
		return nets[0]
	}
	return ""
}
func Fingerprint(r *Reality) string {
	if r == nil || r.Fingerprint == "" {
		return "chrome"
	}
	return r.Fingerprint
}

var domainRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$`)
var idRE = regexp.MustCompile(`^[a-f0-9]{16}$`)
var uuidRE = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var versionRE = regexp.MustCompile(`^1\.14\.(0|[1-9][0-9]*)$`)

func SupportedVersion(v string) bool { return versionRE.MatchString(v) }
func ValidHost(s string) bool {
	return s != "" && len(s) <= 253 && (net.ParseIP(s) != nil || domainRE.MatchString(s))
}
func cleanName(s string) bool {
	if s == "" || len(s) > 160 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (s State) Validate() error {
	if s.CoreArchiveSHA256 != "" {
		b, e := hex.DecodeString(s.CoreArchiveSHA256)
		if e != nil || len(b) != 32 {
			return errors.New("保存的核心归档摘要无效")
		}
	}
	if s.Firewall != "" && s.Firewall != "ufw" {
		return errors.New("自动防火墙仅支持已启用的 UFW；其他后端使用手动模式")
	}
	if s.Schema != Schema {
		return fmt.Errorf("不支持状态格式 %d（当前 %d），请使用匹配的管理器迁移", s.Schema, Schema)
	}
	if !SupportedVersion(s.CoreVersion) {
		return fmt.Errorf("未适配核心版本 %q，仅接受 1.14.x 正式版本", s.CoreVersion)
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	ports := map[string]bool{}
	for _, n := range s.Nodes {
		for _, stamp := range []string{n.CreatedAt, n.UpdatedAt} {
			if stamp != "" {
				if _, e := time.Parse(time.RFC3339Nano, stamp); e != nil {
					return errors.New("节点时间戳无效")
				}
			}
		}
		if !idRE.MatchString(n.ID) || ids[n.ID] {
			return errors.New("节点 ID 无效或重复")
		}
		ids[n.ID] = true
		if !cleanName(n.Name) || names[n.Name] {
			return errors.New("节点名称为空、重复或包含控制字符")
		}
		names[n.Name] = true
		adapter, ok := Protocol(n.Protocol)
		if !ok {
			return fmt.Errorf("不支持协议 %q", n.Protocol)
		}
		if !ValidHost(n.Host) || net.ParseIP(n.Listen) == nil || n.Port < 1 || n.Port > 65535 {
			return fmt.Errorf("节点 %s 的地址/监听 IP/端口无效", n.Name)
		}
		for _, network := range adapter.Networks {
			p := fmt.Sprintf("%s/%d", network, n.Port)
			if n.Enabled && ports[p] {
				return fmt.Errorf("端口冲突：%s", p)
			}
			if n.Enabled {
				ports[p] = true
			}
		}
		if len(n.Users) == 0 {
			return fmt.Errorf("节点 %s 至少需要一个凭据", n.Name)
		}
		users := map[string]bool{}
		unames := map[string]bool{}
		credentials := map[string]bool{}
		for _, u := range n.Users {
			if !idRE.MatchString(u.ID) || users[u.ID] || !cleanName(u.Name) || unames[u.Name] {
				return errors.New("凭据 ID/名称无效或重复")
			}
			users[u.ID] = true
			unames[u.Name] = true
			c := u.UUID + "/" + u.Password
			if credentials[c] {
				return errors.New("同一节点的认证信息重复")
			}
			credentials[c] = true
		}
		if e := adapter.Validate(n); e != nil {
			return fmt.Errorf("节点 %s：%w", n.Name, e)
		}
	}
	return nil
}

// Keep expired but structurally valid certificates readable for backup/disable/repair.
func ValidateCertificateDates(s State) error {
	for _, n := range s.Nodes {
		if !n.Enabled || n.Certificate == nil || n.Certificate.Mode != "pem" {
			continue
		}
		pair, e := tls.X509KeyPair([]byte(n.Certificate.CertPEM), []byte(n.Certificate.KeyPEM))
		if e != nil {
			return errors.New("PEM 证书或私钥无效")
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return e
		}
		if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
			return fmt.Errorf("节点 %s 证书未生效或已过期；请导入新证书，或先停用此节点", n.Name)
		}
	}
	return nil
}
