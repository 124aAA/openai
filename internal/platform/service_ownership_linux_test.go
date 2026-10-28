package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceOwnershipRejectsWritableAndHardLinkedDefinitions(t *testing.T) {
	dir := t.TempDir()
	expected, err := RenderOpenRC(CoreServiceSpec())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "qingnode")
	if err = os.WriteFile(p, []byte(expected), 0755); err != nil {
		t.Fatal(err)
	}
	m := Manager{Kind: InitOpenRC, DefinitionRoot: dir, ConfigRoot: t.TempDir()}
	if err = m.VerifyOwnership("qingnode", []byte(expected)); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0775); err != nil {
		t.Fatal(err)
	}
	if m.VerifyOwnership("qingnode", []byte(expected)) == nil {
		t.Fatal("group-writable root service accepted")
	}
	if err = os.Chmod(p, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err = os.Link(p, link); err != nil {
		t.Fatal(err)
	}
	if m.VerifyOwnership("qingnode", []byte(expected)) == nil {
		t.Fatal("hard-linked root service accepted")
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, append([]byte(expected), make([]byte, 128<<10)...), 0755); err != nil {
		t.Fatal(err)
	}
	if m.VerifyOwnership("qingnode", []byte(expected)) == nil {
		t.Fatal("oversized service definition accepted")
	}
}
