package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"qingnode/internal/node"
)

type protocolOptionsRequest struct {
	Version   int                    `json:"version"`
	NodeID    string                 `json:"node_id"`
	AnyTLS    *node.AnyTLSOptions    `json:"anytls,omitempty"`
	TUIC      *node.TUICOptions      `json:"tuic,omitempty"`
	Transport *node.TransportOptions `json:"transport,omitempty"`
	Multiplex *node.MultiplexOptions `json:"multiplex,omitempty"`
}

func (a *app) protocols(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		if len(args) > 1 {
			return errors.New("用法：protocols list 或 protocols options --file 私有JSON --preview/--yes")
		}
		list := []node.ProtocolCapability{}
		for _, name := range node.Protocols() {
			c, _ := node.ProtocolCapabilities(name)
			list = append(list, c)
		}
		return monitorJSON(map[string]any{"version": 1, "protocols": list, "core_binary_verified": false, "notice": "接口登记不是当前二进制实测；应用时校验官方摘要、版本、构建标签和候选配置。精确已测版本见本批能力矩阵。"})
	}
	if args[0] != "options" {
		return errors.New("支持protocols list/options")
	}
	f := fs("protocols options")
	file := f.String("file", "", "version:1私有协议设置JSON，未知字段拒绝")
	preview := f.Bool("preview", false, "只读验证并显示真实影响")
	yes := f.Bool("yes", false, "统一应用协议设置")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if *file == "" || (!*preview && !*yes) || *preview && *yes {
		return errors.New("需要--file及--preview或--yes之一")
	}
	raw, err := readTopologyFile(*file)
	if err != nil {
		return err
	}
	if err = checkTopologyJSON(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return errors.New("协议设置含重复、异常拼写、null或额外JSON")
	}
	var request protocolOptionsRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request.Version != 1 {
		return errors.New("协议设置须为version:1的严格对象")
	}
	apply := func(st *node.State) error {
		n, e := st.Find(request.NodeID)
		if e != nil || n.ID != request.NodeID {
			return errors.New("需要节点稳定ID")
		}
		if request.AnyTLS == nil && request.TUIC == nil && request.Transport == nil && request.Multiplex == nil {
			return errors.New("请提供至少一项匹配当前节点协议的设置对象（anytls / tuic / transport / multiplex）")
		}
		if request.AnyTLS != nil {
			if n.Protocol != "anytls" {
				return errors.New("anytls 设置仅适用于 AnyTLS 节点")
			}
			n.AnyTLS = request.AnyTLS
		}
		if request.TUIC != nil {
			if n.Protocol != "tuic" {
				return errors.New("tuic 设置仅适用于 TUIC 节点")
			}
			n.TUIC = request.TUIC
		}
		if request.Transport != nil {
			if !node.ProtocolSupportsTransport(n.Protocol) && n.Protocol != "reality" {
				return errors.New("此协议不支持 transport 传输层设置")
			}
			if request.Transport.Type == "" || request.Transport.Type == "tcp" {
				if *request.Transport != (node.TransportOptions{Type: request.Transport.Type}) {
					return errors.New("恢复默认 TCP 传输层时不能附带其他 transport 参数")
				}
				n.Transport = nil
			} else {
				n.Transport = request.Transport
			}
		}
		if request.Multiplex != nil {
			if !node.ProtocolSupportsMultiplex(n.Protocol) {
				return errors.New("此协议不支持 multiplex 多路复用设置")
			}
			if !request.Multiplex.Enabled {
				if *request.Multiplex != (node.MultiplexOptions{}) {
					return errors.New("停用 multiplex 时请使用空对象 {} 或不附带其他参数")
				}
				n.Multiplex = nil
			} else {
				n.Multiplex = request.Multiplex
			}
		}
		return st.Validate()
	}
	if *preview {
		return a.store.InspectExisting(func() error {
			before, e := a.store.Load()
			if e != nil {
				return e
			}
			after := before.Clone()
			if e = apply(&after); e != nil {
				return e
			}
			impact, e := a.store.Preview(after)
			if e != nil {
				return e
			}
			fmt.Println("只读协议设置预览；未修改凭据、配置或服务。")
			return monitorJSON(impact)
		})
	}
	return a.mutate(apply)
}
