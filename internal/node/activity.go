package node

import "errors"

// BackendActivity preserves observation errors for real service backends while
// retaining the established bool-only contract of isolated/offline backends.
func BackendActivity(b Backend) (bool, error) {
	if b == nil {
		return false, errors.New("服务后端不可用，运行状态未知")
	}
	if observer, ok := b.(ActivityBackend); ok {
		return observer.ActiveState()
	}
	return b.Active(), nil
}
