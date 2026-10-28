package node

import (
	_ "embed"
	"errors"

	"qingnode/internal/platform"
)

//go:embed qingnode.service
var ServiceUnit string

// ServiceDefinition renders local target-platform data. Backup service text is
// evidence only and never executed or installed during cross-system restoration.
func ServiceDefinition(kind platform.InitKind) (string, error) {
	switch kind {
	case platform.InitSystemd:
		return ServiceUnit, nil
	case platform.InitOpenRC:
		return platform.RenderOpenRC(platform.CoreServiceSpec())
	default:
		return "", errors.New("仅支持 systemd 或 OpenRC 服务定义")
	}
}

func (b SystemBackend) ServiceManager() platform.Manager {
	return platform.NewManager(b.ManagerKind, platform.CommandRunner(b.Execute))
}
