package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func privateInstallTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// testing.TempDir's numbered child uses 0777 masked by the caller's umask;
	// the real bootstrap uses mktemp -d (0700). Keep that security requirement.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInstallCollectionReusesFormWithoutStateOrCredentials(t *testing.T) {
	dir := privateInstallTestDir(t)
	path := filepath.Join(dir, "fields")
	a := app{in: bufio.NewReader(strings.NewReader("main\n203.0.113.7\n8443\nexample.com\nacme\nadmin@example.com\n"))}
	a.wizardCollect = func(fields []string) error { return writeInstallFields(path, fields) }
	if err := a.installWizardOptions(true, "hysteria2", true, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"qingnode-install-fields-v1", "--name", "main", "--protocol", "hysteria2", "--server", "203.0.113.7", "--quiet", "--auto", "--port", "8443", "--sni", "example.com", "--acme-email", "admin@example.com", ""}
	if !reflect.DeepEqual(strings.Split(string(b), "\x00"), want) {
		t.Fatal("collected fields differ; no generated identity should be present")
	}
	entries, _ := os.ReadDir(dir)
	info, _ := os.Stat(path)
	if len(entries) != 1 || info.Mode().Perm() != 0600 || a.store != nil {
		t.Fatal("collection created State or an unsafe file")
	}
}

func TestInstallCollectionCancellationAndInvalidInputWriteNothing(t *testing.T) {
	for _, input := range []string{":cancel\n", "", "main\nbad host\n", "main\n203.0.113.7\n443\nexample.com\npem\n/no-cert\n/no-key\n"} {
		t.Run(input, func(t *testing.T) {
			dir := privateInstallTestDir(t)
			a := app{in: bufio.NewReader(strings.NewReader(input))}
			a.wizardCollect = func(fields []string) error { return writeInstallFields(filepath.Join(dir, "fields"), fields) }
			err := a.installWizardOptions(true, "hysteria2", true, false)
			if err == nil {
				t.Fatal("invalid or canceled form succeeded")
			}
			if input == "" && !errors.Is(err, io.EOF) {
				t.Fatal("EOF was not preserved")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("canceled or invalid form left output")
			}
		})
	}
}

func TestInstallCollectionRefusesUnsafeFilesAndFutureFormat(t *testing.T) {
	fields := []string{"--protocol", "hysteria2", "--server", "203.0.113.7", "--sni", "example.com", "--acme-email", "admin@example.com"}
	dir := privateInstallTestDir(t)
	path := filepath.Join(dir, "fields")
	if err := writeInstallFields(path, fields); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	if err := writeInstallFields(path, fields); err == nil {
		t.Fatal("overwrote collected fields")
	}
	after, _ := os.ReadFile(path)
	if string(original) != string(after) {
		t.Fatal("existing file changed")
	}
	if err := os.WriteFile(path, []byte("qingnode-install-fields-v2\x00--protocol\x00hysteria2\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&app{}).applyCollectedInstall(path, "hysteria2"); err == nil {
		t.Fatal("future fields format accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeInstallFields(filepath.Join(dir, "other"), fields); err == nil {
		t.Fatal("unsafe output directory accepted")
	}
}
