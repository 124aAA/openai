package node

import (
	"encoding/json"
	"errors"
	"strings"

	"qingnode/internal/subscription"
)

func validateMigrationCoverage(m MigrationPackage) error {
	missing, err := MigrationMissingAssets(m)
	if err != nil {
		return err
	}
	if len(missing) > 0 && m.Mode == "complete" {
		return errors.New("完整迁移包缺少必需资产：" + strings.Join(missing, "；"))
	}
	if len(missing) > 0 && len(m.External) == 0 {
		return errors.New("受限迁移包未列出缺失资产")
	}
	return nil
}

// MigrationMissingAssets checks the authenticated content, rather than trusting
// a caller's "complete" label or the mere existence of an ACME directory.
// Expired assets remain recovery material; runtime date checks are separate.
func MigrationMissingAssets(m MigrationPackage) ([]string, error) {
	roots := map[string]MigrationRoot{}
	files := map[string]MigrationFile{}
	for _, r := range m.Roots {
		roots[r.ID] = r
	}
	for _, f := range m.Files {
		if !f.Directory {
			files[f.RootID+"/"+f.Path] = f
		}
	}
	missing := []string{}
	acmeResources := 0
	for _, r := range m.Snapshot.State.Certificates {
		if r.Certificate.Mode == "file" {
			missing = append(missing, r.ID+":外部证书文件 "+r.Certificate.CertificatePath, r.ID+":外部私钥文件 "+r.Certificate.KeyPath)
		}
		if r.Certificate.Mode != "acme" {
			continue
		}
		acmeResources++
		if _, ok := roots["acme"]; !ok {
			missing = append(missing, r.ID+":ACME存储未包含")
			continue
		}
		certPath, certKeyPath, accountPath, accountKeyPath := migrationACMEPaths(r)
		cert, cok := files["acme/"+certPath]
		certKey, kok := files["acme/"+certKeyPath]
		meta, mok := files["acme/"+strings.TrimSuffix(certPath, ".crt")+".json"]
		pair := false
		if cok && kok && mok && rejectSnapshotEnvelopeDuplicates(meta.Data) == nil {
			leaf, _, e := parseCertificateChain(cert.Data, certKey.Data)
			pair = e == nil && leaf.VerifyHostname(r.Certificate.ServerName) == nil
		}
		reg, rok := files["acme/"+accountPath]
		accountKey, aok := files["acme/"+accountKeyPath]
		account := rok && aok && validMigrationACMEAccount(reg.Data, r.Certificate.Email) && validMigrationACMEAccountKey(accountKey.Data)
		if !pair {
			missing = append(missing, r.ID+":ACME已签发证书/匹配私钥/SAN未包含")
		}
		if !account {
			missing = append(missing, r.ID+":指定CA/email的ACME账户元数据/私钥未包含或结构无效")
		}
	}
	if _, ok := roots["acme"]; ok && acmeResources == 0 {
		return nil, errors.New("迁移包携带未被State声明的ACME根")
	}
	_, sub := roots["subscription"]
	_, pub := roots["publisher"]
	if sub != pub {
		return nil, errors.New("订阅完整迁移必须同时包含发布配置和私有快照目录")
	}
	if sub {
		if len(m.Files) == 0 {
			return nil, errors.New("订阅迁移内容为空")
		}
		marker, mok := files["subscription/"+subscription.MarkerName]
		snapshot, sok := files["subscription/"+subscription.SnapshotName]
		config, cok := files["publisher/subscription-publisher.json"]
		if !mok || !sok || !cok || marker.Mode != 0640 || snapshot.Mode != 0640 || config.Mode != 0600 || string(marker.Data) != subscription.OwnerMarker {
			return nil, errors.New("迁移包缺少私有订阅配置/快照/所有权标记或权限不符")
		}
		for _, f := range m.Files {
			if f.RootID == "publisher" && f.Path != "subscription-publisher.json" || f.RootID == "subscription" && (f.Directory || f.Path != subscription.MarkerName && f.Path != subscription.SnapshotName) {
				return nil, errors.New("订阅迁移含未知条目")
			}
		}
		s, e := subscription.Decode(snapshot.Data)
		if e != nil {
			return nil, errors.New("迁移订阅快照无效")
		}
		c, e := decodeMigrationPublisher(config.Data)
		if e != nil {
			return nil, e
		}
		if c.Directory != roots["subscription"].Source || c.GroupID != roots["subscription"].GroupID {
			return nil, errors.New("订阅发布配置与迁移根路径/属组不一致")
		}
		devices := map[string]DeviceProfile{}
		for _, p := range m.Snapshot.State.Devices {
			devices[p.ID] = p
		}
		for _, record := range s.Records {
			if record.Revoked {
				continue
			}
			p, ok := devices[record.DeviceID]
			if !ok || p.Disabled {
				return nil, errors.New("订阅快照仍授权未启用或不存在的设备")
			}
		}
	}
	return missing, nil
}

type migrationPublisher struct {
	Version   int
	Directory string
	GroupID   int
}

func decodeMigrationPublisher(b []byte) (migrationPublisher, error) {
	var raw map[string]json.RawMessage
	if len(b) > 32768 || rejectMigrationJSON(b) != nil || json.Unmarshal(b, &raw) != nil {
		return migrationPublisher{}, errors.New("迁移发布配置格式无效")
	}
	allowed := map[string]bool{"version": true, "directory": true, "group_id": true, "formats": true, "sing_box_version": true, "mihomo_version": true, "allow_lossy": true}
	for key := range raw {
		if !allowed[key] {
			return migrationPublisher{}, errors.New("迁移发布配置含未知字段")
		}
	}
	var c migrationPublisher
	if json.Unmarshal(raw["version"], &c.Version) != nil || json.Unmarshal(raw["directory"], &c.Directory) != nil || json.Unmarshal(raw["group_id"], &c.GroupID) != nil || c.Version != 1 || c.GroupID < -1 {
		return c, errors.New("迁移发布配置版本、路径或组无效")
	}
	var formats []string
	var sing, mihomo string
	var allow bool
	if json.Unmarshal(raw["formats"], &formats) != nil || json.Unmarshal(raw["sing_box_version"], &sing) != nil || json.Unmarshal(raw["mihomo_version"], &mihomo) != nil || json.Unmarshal(raw["allow_lossy"], &allow) != nil || len(formats) < 1 || len(formats) > 5 || sing != "1.14.0" && sing != "1.14.3" || mihomo != "1.19.30" {
		return c, errors.New("迁移发布配置客户端能力无效")
	}
	seen := map[string]bool{}
	for _, f := range formats {
		if _, ok := subscription.ContentType(f); !ok || seen[f] {
			return c, errors.New("迁移发布格式无效")
		}
		seen[f] = true
	}
	return c, nil
}
