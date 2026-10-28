package main

import (
	"errors"
	"strings"
	"testing"
)

type uncertainMigrationBackend struct {
	*migrationCLIBackend
	observationErr error
}

func (b *uncertainMigrationBackend) ActiveState() (bool, error) {
	return b.active, b.observationErr
}

func TestMigrationUnknownInitialActivityDoesNotStopOrCopy(t *testing.T) {
	a, state := batchFixture(t)
	b := &uncertainMigrationBackend{migrationCLIBackend: &migrationCLIBackend{batchBackend: &batchBackend{active: true}}, observationErr: errors.New("controller disconnected")}
	a.store.Backend = b
	copied := false
	err := a.withStoppedMigration(state, true, func() error { copied = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "尚未停止") || copied || b.stops != 0 || b.starts != 0 || !b.active {
		t.Fatal("unknown controller state mutated migration or service", err, copied, b.stops, b.starts)
	}
}

func TestMigrationUnknownFinalActivityDoesNotBlindlyReactivate(t *testing.T) {
	a, state := batchFixture(t)
	b := &uncertainMigrationBackend{migrationCLIBackend: &migrationCLIBackend{batchBackend: &batchBackend{active: true}}}
	a.store.Backend = b
	copied := false
	err := a.withStoppedMigration(state, true, func() error {
		copied = true
		b.observationErr = errors.New("controller disconnected after snapshot")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "未盲目") || !copied || b.stops != 1 || b.starts != 0 || b.active {
		t.Fatal("unknown final state caused an unverified activation", err, copied, b.stops, b.starts)
	}
}
