package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"qingnode/internal/node"
)

// Certificate input is private management data, never arbitrary core JSON.
type certificateRequest struct {
	Version  int                      `json:"version"`
	Resource node.CertificateResource `json:"resource"`
}

func decodeCertificateRequest(raw []byte) (certificateRequest, error) {
	var request certificateRequest
	if len(raw) > maxBatchBytes {
		return request, errors.New("证书输入超过1MiB")
	}
	if err := checkTopologyJSON(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return request, errors.New("证书输入含重复、异常拼写、null或额外JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request.Version != 1 {
		return request, errors.New("证书输入须为version:1和一个resource，不接受未知字段")
	}
	return request, nil
}

func certificateIndex(st node.State, selector string) (int, error) {
	for i, resource := range st.Certificates {
		if resource.ID == selector {
			return i, nil
		}
	}
	for i, resource := range st.Certificates {
		if resource.Name == selector {
			return i, nil
		}
	}
	return -1, errors.New("证书资源不存在；请用certificate list查看稳定ID")
}

func (a *app) certificates(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：certificate list/status/import/update/bind/unbind/remove；私钥及DNS凭据只从私有--file读取")
	}
	command := args[0]
	f := fs("certificate " + command)
	id := f.String("id", "", "证书稳定ID或名称")
	nodeID := f.String("node", "", "要绑定的本地节点ID或名称")
	replacement := f.String("replace", "", "解除旧引用时替换为此证书；HY2不能没有TLS证书")
	file := f.String("file", "", "权限600的version:1证书资源JSON，最多1MiB")
	preview := f.Bool("preview", false, "只读校验及影响预览，不保存、不签发、不启停服务")
	yes := f.Bool("yes", false, "确认更新共享证书或删除未引用资源")
	out := f.String("out", "", "将不含私钥或DNS凭据的状态JSON写入新的私有文件")
	if err := parse(f, args[1:]); err != nil {
		return err
	}
	if command == "list" || command == "status" {
		if err := rejectTopologyFlags(f, "id", "out"); err != nil {
			return err
		}
		return a.store.InspectExisting(func() error {
			st, err := a.store.Load()
			if err != nil {
				return err
			}
			indexes := []int{}
			if *id != "" {
				i, err := certificateIndex(st, *id)
				if err != nil {
					return err
				}
				indexes = append(indexes, i)
			} else {
				for i := range st.Certificates {
					indexes = append(indexes, i)
				}
			}
			reports := []any{}
			for _, i := range indexes {
				resource := st.Certificates[i]
				status, err := node.InspectCertificateResource(resource, a.store.Root, time.Now().UTC())
				// Inspection errors become a safe failed observation. They do not
				// repair files, trigger issuance, or change the running node.
				report := map[string]any{"id": resource.ID, "name": resource.Name, "mode": resource.Certificate.Mode, "nodes": node.CertificateReferences(st, resource.ID), "status": status}
				if err != nil {
					report["inspection_error"] = node.Redact(err.Error(), st)
				}
				if resource.Certificate.Mode == "acme" {
					// A single explicit status target bounds journal work. Listing
					// hundreds of resources must not run hundreds of system queries.
					if command == "status" && *id != "" {
						if observer, ok := a.store.Backend.(interface {
							InspectCertificateJournal(node.State, node.CertificateResource, time.Time) (node.CertificateJournalObservation, error)
						}); ok {
							observation, observationErr := observer.InspectCertificateJournal(st, resource, time.Now().UTC())
							report["acme_events"] = observation
							if observationErr != nil {
								report["acme_events_error"] = node.Redact(observationErr.Error(), st)
							}
						} else {
							report["acme_events_limitation"] = "当前后端没有可验证的核心日志观测；最近签发、失败与签发中状态未知"
						}
					} else {
						report["acme_events_limitation"] = "运行事件请使用 certificate status --id 证书ID；列表只观察当前证书资产"
					}
				}
				reports = append(reports, report)
			}
			raw, err := json.MarshalIndent(map[string]any{"version": 1, "checked_at": time.Now().UTC(), "certificates": reports, "issuance_triggered": false}, "", "  ")
			if err != nil {
				return err
			}
			return writeOutput(*out, raw)
		})
	}
	var supplied node.CertificateResource
	switch command {
	case "import", "update":
		if err := rejectTopologyFlags(f, "id", "file", "preview", "yes"); err != nil {
			return err
		}
		if *file == "" {
			return errors.New("请用--file提供私有证书资源JSON；不接受命令行私钥或DNS Token")
		}
		raw, err := readTopologyFile(*file)
		if err != nil {
			return err
		}
		request, err := decodeCertificateRequest(raw)
		if err != nil {
			return err
		}
		supplied = request.Resource
		if command == "import" {
			if *id != "" {
				return errors.New("import的稳定ID在resource中提供；省略时生成")
			}
			if supplied.ID == "" {
				supplied.ID = node.Token(8)
			}
		} else if *id == "" || !*preview && !*yes {
			return errors.New("更新共享证书需要--id与--yes；可先--preview查看引用节点")
		}
	case "bind":
		if err := rejectTopologyFlags(f, "id", "node", "preview"); err != nil {
			return err
		}
		if *id == "" || *nodeID == "" {
			return errors.New("绑定需要--id证书及--node节点")
		}
	case "unbind":
		if err := rejectTopologyFlags(f, "id", "node", "replace", "preview", "yes"); err != nil {
			return err
		}
		if *id == "" || *nodeID == "" || *replacement == "" || !*preview && !*yes {
			return errors.New("HY2需要TLS；解除旧引用请提供--id旧证书 --node节点 --replace新证书 --yes，或先--preview")
		}
	case "remove":
		if err := rejectTopologyFlags(f, "id", "preview", "yes"); err != nil {
			return err
		}
		if *id == "" || !*preview && !*yes {
			return errors.New("删除需要--id与--yes；有引用的证书会拒绝删除")
		}
	default:
		return errors.New("未知certificate操作；支持list/status/import/update/bind/unbind/remove")
	}
	return a.changeTopology(*preview, func(st *node.State) error {
		var next node.State
		var err error
		switch command {
		case "import", "update":
			if command == "update" {
				i, err := certificateIndex(*st, *id)
				if err != nil {
					return err
				}
				original := st.Certificates[i]
				if supplied.ID != "" && supplied.ID != original.ID {
					return errors.New("更新不能更换证书稳定ID")
				}
				supplied.ID = original.ID
				supplied.LegacyStorage = original.LegacyStorage && supplied.Certificate.Mode == "acme"
				fmt.Fprintf(os.Stderr, "共享证书%s引用节点：%v；可能重启共享核心，已有连接可能中断。\n", original.ID, node.CertificateReferences(*st, original.ID))
			} else {
				for _, existing := range st.Certificates {
					if existing.ID == supplied.ID {
						return errors.New("证书ID已存在；更新请使用update并先预览")
					}
				}
				if supplied.LegacyStorage {
					return errors.New("新导入不能声明旧ACME存储归属")
				}
			}
			if err := node.ValidateCertificateResource(supplied, time.Now().UTC(), true); err != nil {
				return errors.New("候选证书校验失败，已有证书和运行配置保持；请核对域名、证书链、有效期、私钥及受支持算法")
			}
			next, err = node.PutCertificateResource(*st, supplied)
		case "remove":
			i, e := certificateIndex(*st, *id)
			if e != nil {
				return e
			}
			next, err = node.RemoveCertificateResource(*st, st.Certificates[i].ID)
		case "bind", "unbind":
			i, e := certificateIndex(*st, *id)
			if e != nil {
				return e
			}
			certificateID := st.Certificates[i].ID
			if command == "unbind" {
				n, e := st.Find(*nodeID)
				if e != nil {
					return e
				}
				if n.CertificateID != certificateID {
					return errors.New("节点未引用指定旧证书")
				}
				j, e := certificateIndex(*st, *replacement)
				if e != nil {
					return e
				}
				certificateID = st.Certificates[j].ID
				if certificateID == st.Certificates[i].ID {
					return errors.New("替换证书不能仍是原证书")
				}
			}
			next, err = node.BindCertificate(*st, *nodeID, certificateID)
		}
		if err == nil {
			*st = next
		}
		return err
	})
}
