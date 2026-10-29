//go:build windows

package exporter

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/danieljoos/wincred"
)

func TestReadCredentialUsesIloaderWindowsTarget(t *testing.T) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	entry := "sidecert-test-" + hex.EncodeToString(random) + "/key"
	cred := wincred.NewGenericCredential(entry + ".iloader")
	cred.CredentialBlob = []byte{0, 1, 2, 0xfe, 0xff}
	if err := cred.Write(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cred.Delete(); err != nil {
			t.Error(err)
		}
	})
	got, err := readCredential(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cred.CredentialBlob) {
		t.Fatal("credential blob did not round trip")
	}
}
