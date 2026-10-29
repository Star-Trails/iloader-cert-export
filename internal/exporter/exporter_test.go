package exporter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

func TestOfflineExportMatchesKeyAndCertificate(t *testing.T) {
	now := time.Now()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Test developer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	content, err := plist.Marshal(map[string]any{"TeamIdentifier": []string{"TESTTEAM"}, "TeamName": "Test", "DeveloperCertificates": [][]byte{der}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	cms, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("APPDATA", root)
	dir := filepath.Join(root, "me.nabdev.iloader")
	sum := sha256.Sum256([]byte("fixture@example.com"))
	keydir := filepath.Join(dir, hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(keydir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keydir, "key"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test.mobileprovision"), cms, 0600); err != nil {
		t.Fatal(err)
	}
	service, _ := New(Config{})
	result, err := service.Export(context.Background(), Request{AppleID: "fixture@example.com", OutputDir: root, P12Password: "test-password"}, Callbacks{})
	if err != nil {
		t.Fatal(err)
	}
	p12, err := os.ReadFile(result.P12Path)
	if err != nil {
		t.Fatal(err)
	}
	actualKey, actualCert, err := pkcs12.Decode(p12, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !actualCert.Equal(cert) || !actualKey.(*rsa.PrivateKey).Equal(key) || result.TeamID != "TESTTEAM" {
		t.Fatal("exported identity does not match local signing identity")
	}
	if _, _, err := pkcs12.Decode(p12, "wrong-password"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	found, _, err := matchingCertificate(dir, other, now)
	if err != nil || found != nil {
		t.Fatal("unrelated key matched the certificate")
	}
}
