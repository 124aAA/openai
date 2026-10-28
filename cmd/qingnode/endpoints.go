package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"qingnode/internal/node"
)

func rejectPending(root string) error {
	for _, name := range []string{"transaction.json", "uninstall.json"} {
		_, err := os.Lstat(filepath.Join(root, name))
		if err == nil {
			return errors.New("存在中断事务；只读操作不自动恢复，请先显式 recover")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// No provider API or host-network operation is involved in declaring endpoints.
func (a *app) endpoint(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：endpoint list|add|edit|remove|material --id 节点 [--endpoint default或端点ID]；声明不会改变云NAT")
	}
	action := args[0]
	f := fs("endpoint " + action)
	id := f.String("id", "", "节点ID或名称")
	ep := f.String("endpoint", "default", "连接端点ID；default是主入口")
	host := f.String("server", "", "客户端连接的IP或域名，独立于TLS名称")
	port := namedPortFlag(f, "connect-port", 0, "外部客户端连接端口（十进制1–65535）")
	preview := f.Bool("preview", false, "只读预览影响，不保存或恢复事务")
	out := f.String("out", "", "material的新JSON文件；不含凭据")
	machine := f.Bool("json", false, "仅list：版本1监听与连接端点声明，不含代理凭据")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if flagSet(f, "json") && action != "list" {
		return errors.New("--json仅用于endpoint list；material本身输出版本化JSON")
	}
	switch action {
	case "list", "material", "add", "edit", "remove":
	default:
		return errors.New("未知端点操作")
	}
	if *id == "" {
		return errors.New("需要--id")
	}
	if *out != "" && action != "material" {
		return errors.New("--out只用于material")
	}
	if action == "list" || action == "material" {
		if flagSet(f, "server") || flagSet(f, "connect-port") || *preview {
			return errors.New("查询不接受修改参数")
		}
		if *out != "" {
			if err := a.probeOutput(*out); err != nil {
				return err
			}
		}
		return a.inspectState(func(s *node.State) error {
			if err := s.Validate(); err != nil {
				return err
			}
			n, err := s.Find(*id)
			if err != nil {
				return err
			}
			if action == "list" {
				if *machine {
					return queryJSON("qingnode-endpoint-declarations", struct {
						NodeID          string                    `json:"node_id"`
						ListenAddress   string                    `json:"listen_address"`
						ListenPort      int                       `json:"listen_port"`
						Networks        []string                  `json:"listener_networks"`
						Endpoints       []node.ConnectionEndpoint `json:"connection_endpoints"`
						PublicIngress   string                    `json:"public_ingress"`
						CloudNATChanged bool                      `json:"cloud_nat_changed"`
					}{n.ID, n.Listen, n.Port, node.Networks(*n), node.EffectiveEndpoints(*n), "unknown", false})
				}
				for _, p := range node.EffectiveEndpoints(*n) {
					fmt.Printf("%s  %s  %v -> 本地 %s（声明，外部未验证）\n", p.ID, net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), node.Networks(*n), net.JoinHostPort(n.Listen, strconv.Itoa(n.Port)))
				}
				return nil
			}
			selected, err := node.WithEndpoint(*n, *ep)
			if err != nil {
				return err
			}
			server, err := node.Server(*s, a.store.Root)
			if err != nil {
				return err
			}
			client := []node.M{}
			for _, u := range selected.Users {
				client = append(client, node.Outbound(selected, u))
			}
			raw, _ := json.Marshal(client)
			serverSHA := sha256.Sum256(server)
			clientSHA := sha256.Sum256(raw)
			families := []string{"ipv4", "ipv6"}
			kind := "domain"
			if ip := net.ParseIP(selected.Host); ip != nil {
				kind = "ipv6"
				families = []string{"ipv6"}
				if ip.To4() != nil {
					kind = "ipv4"
					families = []string{"ipv4"}
				}
			}
			report := map[string]any{"version": 1, "generated_at": time.Now().UTC(), "node_id": n.ID, "endpoint_id": *ep, "origin": "manager configuration declaration; no external measurement", "listener": map[string]any{"address": n.Listen, "port": n.Port, "networks": node.Networks(*n)}, "connection": map[string]any{"host": selected.Host, "port": node.EffectiveConnectPort(selected), "kind": kind}, "families_to_verify": families, "required_mappings": []any{}, "dns_a": "unknown", "dns_aaaa": "unknown", "inbound_tcp": "unknown", "inbound_udp": "unknown", "cloud_nat_changed": false, "server_config_sha256": hex.EncodeToString(serverSHA[:]), "client_config_sha256": hex.EncodeToString(clientSHA[:]), "instructions": []string{"从真正客户端网络分别验证A/AAAA，不能用VPS出口IP推断入站地址。", "TCP与UDP分别验证；TCP连接成功不等于代理认证或UDP成功。", "qingnode probe profile --id 节点ID --endpoint 端点ID --out 私密资料.json，然后在实际客户端用qingprobe run --path client-proxy --profile 私密资料.json测试。", "域名自动回落到IPv4的成功不能证明AAAA可达；需独立IPv6字面量端点和对应实际客户端链路测试。", "私密Profile含凭据，不放入本材料，不公开上传。"}}
			mappings := []any{}
			for _, network := range node.Networks(*n) {
				mappings = append(mappings, map[string]any{"network": network, "external_host": selected.Host, "external_port": node.EffectiveConnectPort(selected), "local_address": n.Listen, "local_port": n.Port, "status": "unverified"})
			}
			report["required_mappings"] = mappings
			if n.Certificate != nil && n.Certificate.Mode == "acme" {
				report["acme_http01"] = "另需证书域名的外部TCP80到本机TCP80；节点UDP/TCP映射不证明满足签发条件"
			}
			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			return writeOutput(*out, []byte(node.Redact(string(b), *s)+"\n"))
		})
	}
	if *out != "" {
		return errors.New("修改不写结果文件")
	}
	if flagSet(f, "server") {
		h, err := node.NormalizeEndpointHost(*host)
		if err != nil {
			return err
		}
		*host = h
	}
	if flagSet(f, "connect-port") && (*port < 1 || *port > 65535) {
		return errors.New("连接端口须为1–65535")
	}
	change := func(s *node.State) error {
		n, err := s.Find(*id)
		if err != nil {
			return err
		}
		edit := nodeEdit{ID: n.ID}
		if *ep == "default" {
			if action != "edit" {
				return errors.New("default主入口只可edit；其它入口使用显式ID")
			}
			if flagSet(f, "server") {
				edit.Server = host
			}
			if flagSet(f, "connect-port") {
				edit.ConnectPort = port
			}
		} else {
			items := append([]node.ConnectionEndpoint{}, n.AdditionalEndpoints...)
			index := -1
			for i, p := range items {
				if p.ID == *ep {
					index = i
				}
			}
			switch action {
			case "add":
				if index >= 0 {
					return errors.New("端点ID已存在")
				}
				if !flagSet(f, "server") || !flagSet(f, "connect-port") {
					return errors.New("add需要--server和--connect-port")
				}
				items = append(items, node.ConnectionEndpoint{ID: *ep, Host: *host, Port: *port})
			case "edit":
				if index < 0 {
					return errors.New("端点不存在")
				}
				if flagSet(f, "server") {
					items[index].Host = *host
				}
				if flagSet(f, "connect-port") {
					items[index].Port = *port
				}
			case "remove":
				if flagSet(f, "server") || flagSet(f, "connect-port") {
					return errors.New("remove不接受连接值")
				}
				if index < 0 {
					return errors.New("端点不存在")
				}
				items = append(items[:index], items[index+1:]...)
			}
			edit.AdditionalEndpoints = &items
		}
		if edit.empty() {
			return errors.New("需要至少一个修改字段")
		}
		_, err = applyNodeEdits(s, []nodeEdit{edit})
		return err
	}
	if *preview {
		return a.store.InspectExisting(func() error {
			if err := rejectPending(a.store.Root); err != nil {
				return err
			}
			s, err := a.store.Load()
			if err != nil {
				return err
			}
			if err = change(&s); err != nil {
				return err
			}
			impact, err := a.store.Preview(s)
			if err != nil {
				return err
			}
			printChangeImpact(impact)
			fmt.Println("只读端点预览：未改变云NAT、节点或服务。")
			return nil
		})
	}
	return a.mutate(change)
}
