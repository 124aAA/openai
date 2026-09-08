package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
	"gopkg.in/yaml.v3"
)

type M = map[string]any

func Server(s State, root string) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	in := []any{}
	for _, n := range s.Nodes {
		if !n.Enabled {
			continue
		}
		adapter, _ := Protocol(n.Protocol)
		config := adapter.Inbound(n, root)
		config["tag"] = n.ID
		config["listen"] = n.Listen
		config["listen_port"] = n.Port
		in = append(in, config)
	}
	return json.MarshalIndent(M{"log": M{"level": "warn", "timestamp": true}, "dns": M{"servers": []any{M{"type": "local", "tag": "system"}}}, "inbounds": in, "outbounds": []any{M{"type": "direct", "tag": "direct"}}, "route": M{"final": "direct", "default_domain_resolver": "system"}}, "", "  ")
}
func SelectUser(n Node, id string) (User, error) {
	if id == "" {
		if len(n.Users) != 1 {
			return User{}, errors.New("此节点有多个凭据，请用 --user 指定")
		}
		return n.Users[0], nil
	}
	for _, u := range n.Users {
		if u.ID == id || u.Name == id {
			return u, nil
		}
	}
	return User{}, errors.New("凭据不存在")
}
func URI(n Node, u User) string {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return ""
	}
	return p.URI(n, u)
}
func Outbound(n Node, u User) M {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	out := p.Outbound(n, u)
	out["tag"] = "proxy"
	out["server"] = n.Host
	out["server_port"] = n.Port
	return out
}
func Client(n Node, u User, port int) M {
	return M{"log": M{"level": "warn"}, "dns": M{"servers": []any{M{"type": "local", "tag": "system"}}}, "inbounds": []any{M{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{Outbound(n, u)}, "route": M{"final": "proxy", "default_domain_resolver": "system"}}
}
func MihomoProxy(n Node, u User) M {
	p, ok := Protocol(n.Protocol)
	if !ok {
		return nil
	}
	out := p.Mihomo(n, u)
	out["name"] = n.Name + " / " + u.Name
	out["server"] = n.Host
	out["port"] = n.Port
	return out
}
func Export(n Node, u User, format string) ([]byte, error) {
	if _, ok := Protocol(n.Protocol); !ok {
		return nil, errors.New("不支持该协议")
	}
	if !n.Enabled {
		return nil, errors.New("节点已停用，启用后才能导出")
	}
	switch format {
	case "uri":
		return []byte(URI(n, u) + "\n"), nil
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString([]byte(URI(n, u)+"\n")) + "\n"), nil
	case "qr":
		q, e := qrcode.New(URI(n, u), qrcode.Medium)
		if e != nil {
			return nil, e
		}
		return []byte(q.ToSmallString(false)), nil
	case "sing-box":
		return json.MarshalIndent(Client(n, u, 2080), "", "  ")
	case "mihomo":
		p := MihomoProxy(n, u)
		return yaml.Marshal(M{"mixed-port": 7890, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning", "proxies": []any{p}, "proxy-groups": []any{M{"name": "PROXY", "type": "select", "proxies": []string{p["name"].(string)}}}, "rules": []string{"MATCH,PROXY"}})
	case "provider":
		return yaml.Marshal(M{"proxies": []any{MihomoProxy(n, u)}})
	default:
		return nil, fmt.Errorf("未知格式 %q；支持 %s", format, strings.Join([]string{"uri", "qr", "base64", "mihomo", "provider", "sing-box"}, ", "))
	}
}
