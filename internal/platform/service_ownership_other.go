//go:build !linux

package platform

import "os"

// Only Linux hosts are deployment targets. Other hosts can exercise pure service
// adapters with injected commands, but cannot attest to Linux UID/link metadata.
func verifyDefinitionFileOwner(os.FileInfo) error { return nil }
