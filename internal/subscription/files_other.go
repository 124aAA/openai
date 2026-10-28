//go:build !linux

package subscription

import "errors"

// The online service's DAC ownership contract is Linux-specific. Portable client
// exports do not need this package's filesystem or server functionality.
func Initialize(string, int) error {
	return errors.New("subscription publication filesystem requires Linux")
}
func CreateInitial(string, int) error {
	return errors.New("subscription publication filesystem requires Linux")
}
func Publish(string, Snapshot, int) error {
	return errors.New("subscription publication filesystem requires Linux")
}
func Read(string) (Snapshot, error) {
	return Snapshot{}, errors.New("subscription publication filesystem requires Linux")
}
