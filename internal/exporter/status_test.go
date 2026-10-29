package exporter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestCertificateStatusChecksSignedOCSP(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	status := ocsp.Good
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := ocsp.CreateResponse(root, root, ocsp.Response{Status: status, SerialNumber: big.NewInt(2), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedAt: now.Add(-time.Minute)}, key)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(response)
	}))
	defer server.Close()
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), OCSPServer: []string{server.URL}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkStatus(context.Background(), leaf, root, server.URL); !strings.Contains(got, "Certificate valid") {
		t.Fatalf("expected good status: %s", got)
	}
	status = ocsp.Revoked
	if got := checkStatus(context.Background(), leaf, root, server.URL); !strings.Contains(got, "revoked") {
		t.Fatalf("expected revoked status: %s", got)
	}
	if got := checkStatus(context.Background(), leaf, nil, ""); !strings.Contains(got, "unknown") {
		t.Fatalf("untrusted issuer should be unknown: %s", got)
	}
}
