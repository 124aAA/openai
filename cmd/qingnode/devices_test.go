package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"qingnode/internal/node"
)

func deviceProfilesFile(t *testing.T, profiles []node.DeviceProfile) string {
	t.Helper()
	b, err := json.Marshal(deviceBatch{Version: 1, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "devices.json")
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func deviceCLIFixture(t *testing.T) (*app, node.State, *batchBackend) {
	t.Helper()
	a, s := batchFixture(t)
	s.Nodes[0].Users = append(s.Nodes[0].Users, node.NewUser("tablet credential", "ss2022"))
	port := 30000
	s.Nodes[0].Host = "2001:db8::8"
	s.Nodes[0].ConnectPort = &port
	if err := a.store.WithLock(func() error { return a.store.Apply(s) }); err != nil {
		t.Fatal(err)
	}
	backend := &batchBackend{}
	a.store.Backend = backend
	a.store.AfterCommit = a.refreshPublished
	a.store.BeforeCommit = a.revokeRemovedPublishedDevices
	profiles := []node.DeviceProfile{
		{ID: "00000000000000a1", Name: "phone+家/one", Strategy: "manual", Routing: "global", Bindings: []node.DeviceBinding{{NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[0].ID}, {NodeID: s.Nodes[1].ID, UserID: s.Nodes[1].Users[0].ID}}},
		{ID: "00000000000000b2", Name: "tablet", Strategy: "manual", Routing: "global", Bindings: []node.DeviceBinding{{NodeID: s.Nodes[0].ID, UserID: s.Nodes[0].Users[1].ID}}},
	}
	if _, err := wizardOutput(t, func() error { return a.device([]string{"apply", "--file", deviceProfilesFile(t, profiles)}) }); err != nil {
		t.Fatal(err)
	}
	s, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	backend.checks = 0
	backend.activeCalls = 0
	backend.starts = 0
	backend.stops = 0
	return a, s, backend
}

func TestDeviceCLIExplicitCredentialsAndPrivateExports(t *testing.T) {
	a, s, backend := deviceCLIFixture(t)
	beforeGeneration, before := savedBatchState(t, a)
	for i, p := range s.Devices {
		out := filepath.Join(t.TempDir(), "device.json")
		stdout, err := wizardOutput(t, func() error {
			return a.command([]string{"export", "--device", p.ID, "--format", "sing-box", "--client-version", "1.14.0", "--out", out})
		})
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(out)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("device export permissions", err)
		}
		if stdout != "" {
			t.Fatal("private export unexpectedly wrote to stdout")
		}
		if !json.Valid(b) || !strings.Contains(string(b), "2001:db8::8") || !strings.Contains(string(b), "30000") {
			t.Fatal("export lost IPv6/NAT endpoint")
		}
		chosen, other := s.Nodes[0].Users[i], s.Nodes[0].Users[1-i]
		if !bytes.Contains(b, []byte(chosen.Password)) || bytes.Contains(b, []byte(other.Password)) {
			t.Fatal("export chose another device's credential")
		}
		if i == 0 && !bytes.Contains(b, []byte(s.Nodes[1].Users[0].Password)) {
			t.Fatal("multi-node binding omitted second explicit credential")
		}
	}
	for _, args := range [][]string{{"device", "list"}, {"device", "show", "--id", s.Devices[0].ID}, {"device", "tags", "--id", s.Nodes[0].ID, "--tags", "mobile,home", "--preview"}} {
		if _, err := wizardOutput(t, func() error { return a.command(args) }); err != nil {
			t.Fatal(err)
		}
	}
	generation, after := savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("read/export/preview changed State or service")
	}
}

func TestDeviceCLIInvalidWholeBatchAndPreviewPreserveGeneration(t *testing.T) {
	a, s, backend := deviceCLIFixture(t)
	beforeGeneration, before := savedBatchState(t, a)
	profiles := append([]node.DeviceProfile{}, s.Devices...)
	profiles[0].Name = "valid change first"
	profiles[1].Bindings = []node.DeviceBinding{{NodeID: s.Nodes[0].ID, UserID: "ffffffffffffffff"}}
	if err := a.device([]string{"apply", "--file", deviceProfilesFile(t, profiles)}); err == nil {
		t.Fatal("missing explicit credential accepted")
	}
	if err := a.device([]string{"create", "--name", "unbound", "--binding", s.Nodes[0].ID}); err == nil {
		t.Fatal("implicit first-user binding accepted")
	}
	profiles = append([]node.DeviceProfile{}, s.Devices...)
	profiles[0].Name = "preview only"
	if _, err := wizardOutput(t, func() error {
		return a.device([]string{"apply", "--file", deviceProfilesFile(t, profiles), "--preview"})
	}); err != nil {
		t.Fatal(err)
	}
	generation, after := savedBatchState(t, a)
	if generation != beforeGeneration || !bytes.Equal(before, after) || backend.starts != 0 || backend.stops != 0 || backend.checks != 0 || backend.activeCalls != 0 {
		t.Fatal("invalid batch or preview partially changed State/service")
	}
}

func TestDeviceCLISharedCredentialDisableDoesNotRevoke(t *testing.T) {
	a, s, backend, dir, materials := subscriptionCLIFixture(t)
	profiles := append([]node.DeviceProfile{}, s.Devices...)
	profiles[1].Bindings = append(profiles[1].Bindings, node.DeviceBinding{NodeID: s.Nodes[1].ID, UserID: s.Nodes[1].Users[0].ID})
	if err := a.device([]string{"apply", "--file", deviceProfilesFile(t, profiles)}); err != nil {
		t.Fatal(err)
	}
	beforeGeneration, before := savedBatchState(t, a)
	publicationBefore, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = a.device([]string{"disable", "--id", s.Devices[0].ID, "--disable-credentials", "--yes"})
	if err == nil || !strings.Contains(err.Error(), "共享") {
		t.Fatal("shared authentication not refused", err)
	}
	generation, after := savedBatchState(t, a)
	publicationAfter, _ := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if generation != beforeGeneration || !bytes.Equal(before, after) || !bytes.Equal(publicationBefore, publicationAfter) || backend.starts != 0 || backend.stops != 0 {
		t.Fatal("shared-disable refusal changed State, token, or service")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 200 {
		t.Fatal("invalid disable revoked active download")
	}
}

func TestDeviceCLIOrdinaryDisabledDeviceStillProtectsSharedCredential(t *testing.T) {
	for _, sharedNode := range []int{0, 1} {
		for _, active := range []bool{false, true} {
			name := []string{"another-user-remains", "last-node-user"}[sharedNode] + "/" + map[bool]string{false: "stopped", true: "running"}[active]
			t.Run(name, func(t *testing.T) {
				a, st, backend := deviceCLIFixture(t)
				// Both devices receive the same existing proxy credential before
				// publication. Device B also retains its independent credential.
				profiles := st.Clone().Devices
				shared := profiles[0].Bindings[sharedNode]
				profiles[1].Bindings = append(profiles[1].Bindings, shared)
				if _, err := wizardOutput(t, func() error {
					return a.device([]string{"apply", "--file", deviceProfilesFile(t, profiles)})
				}); err != nil {
					t.Fatal(err)
				}
				st, err := a.store.Load()
				if err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(t.TempDir(), "published")
				if err = a.subscription([]string{"init", "--dir", dir}); err != nil {
					t.Fatal(err)
				}
				materials := make([]tokenMaterial, len(st.Devices))
				for i, p := range st.Devices {
					path := filepath.Join(t.TempDir(), "token.json")
					if _, err = subscriptionCLIStderr(t, func() error {
						return a.subscription([]string{"issue", "--device", p.ID, "--out", path})
					}); err != nil {
						t.Fatal(err)
					}
					raw, err := os.ReadFile(path)
					if err != nil || json.Unmarshal(raw, &materials[i]) != nil || materials[i].DeviceID != p.ID || len(materials[i].Token) != 64 {
						t.Fatal("device token fixture was not issued", err)
					}
					code, body := subscriptionCLIGet(t, dir, materials[i].Token)
					if code != 200 || !strings.Contains(body, st.Nodes[sharedNode].Users[0].Password) {
						t.Fatal("shared proxy credential was not published to both devices")
					}
				}
				serverPath := filepath.Join(a.store.Root, "current", "server.json")
				serverBefore, err := os.ReadFile(serverPath)
				if err != nil {
					t.Fatal(err)
				}
				backend.active = active
				backend.checks, backend.activeCalls, backend.starts, backend.stops = 0, 0, 0, 0
				if _, err = subscriptionCLIStderr(t, func() error {
					return a.device([]string{"disable", "--id", st.Devices[1].ID, "--yes"})
				}); err != nil {
					t.Fatal(err)
				}
				disabled, err := a.store.Load()
				if err != nil {
					t.Fatal(err)
				}
				serverAfter, err := os.ReadFile(serverPath)
				if err != nil || !bytes.Equal(serverBefore, serverAfter) || !reflect.DeepEqual(st.Nodes, disabled.Nodes) || disabled.Devices[0].Disabled || !disabled.Devices[1].Disabled {
					t.Fatal("ordinary device disable changed proxy authentication or server configuration", err)
				}
				if backend.active != active || backend.starts != 0 || backend.stops != 0 {
					t.Fatal("ordinary device disable changed the existing service state")
				}
				if code, _ := subscriptionCLIGet(t, dir, materials[1].Token); code != 404 {
					t.Fatal("ordinary disabled device retained download permission")
				}
				code, remainingBody := subscriptionCLIGet(t, dir, materials[0].Token)
				if code != 200 {
					t.Fatal("ordinary disable revoked the other device")
				}
				generationBefore, stateBefore := savedBatchState(t, a)
				publicationPath := filepath.Join(dir, "snapshot.json")
				publicationBefore, err := os.ReadFile(publicationPath)
				if err != nil {
					t.Fatal(err)
				}
				serviceBefore := *backend
				for _, flags := range [][]string{{"--preview"}, {"--yes"}} {
					args := append([]string{"disable", "--id", st.Devices[0].ID, "--disable-credentials"}, flags...)
					_, err = wizardOutput(t, func() error { return a.device(args) })
					if err == nil || !strings.Contains(err.Error(), "共享") {
						t.Fatal("download-disabled device lost its shared-credential protection", err)
					}
					generationAfter, stateAfter := savedBatchState(t, a)
					publicationAfter, publicationErr := os.ReadFile(publicationPath)
					serverAfter, serverErr := os.ReadFile(serverPath)
					if publicationErr != nil || serverErr != nil || generationAfter != generationBefore || !bytes.Equal(stateBefore, stateAfter) || !bytes.Equal(serverBefore, serverAfter) || !bytes.Equal(publicationBefore, publicationAfter) || *backend != serviceBefore {
						t.Fatal("shared-credential refusal changed State, generation, server, publication, or service")
					}
					if code, body := subscriptionCLIGet(t, dir, materials[0].Token); code != 200 || body != remainingBody {
						t.Fatal("refused shared disable changed the active device download")
					}
					if code, _ := subscriptionCLIGet(t, dir, materials[1].Token); code != 404 {
						t.Fatal("refused shared disable revived the other device download")
					}
				}
			})
		}
	}
}

func TestDeviceCLIExclusiveDisablePreservesOtherDeviceAndDisclosesLastUser(t *testing.T) {
	a, s, backend, dir, materials := subscriptionCLIFixture(t)
	original := s.Clone()
	stderr, err := subscriptionCLIStderr(t, func() error {
		return a.device([]string{"disable", "--id", s.Devices[0].ID, "--disable-credentials", "--yes"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "最后一条凭据") || !strings.Contains(stderr, "监听已停用") || !strings.Contains(stderr, "重新启用") {
		t.Fatal("last-user revival consequence missing", stderr)
	}
	after, err := a.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !after.Devices[0].Disabled || after.Devices[1].Disabled || len(after.Nodes[0].Users) != 1 || after.Nodes[0].Users[0].ID != original.Nodes[0].Users[1].ID || !reflect.DeepEqual(after.Nodes[0].Users[0], original.Nodes[0].Users[1]) {
		t.Fatal("disable affected another device credential")
	}
	if after.Nodes[1].Enabled || !reflect.DeepEqual(after.Nodes[1].Users, original.Nodes[1].Users) {
		t.Fatal("last credential must be preserved in disabled listener")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[0].Token); code != 404 {
		t.Fatal("disabled device download remains active")
	}
	if code, _ := subscriptionCLIGet(t, dir, materials[1].Token); code != 200 {
		t.Fatal("unrelated device download revoked")
	}
	// Removing proxy credentials changes the real server configuration. Retain
	// Apply's established runtime-change behavior; ordinary metadata-only
	// deactivation/rollback and publication tests separately require no start.
	if !backend.active || backend.starts != 1 || backend.stops != 0 {
		t.Fatal("credential runtime change did not perform exactly one activation")
	}
}
