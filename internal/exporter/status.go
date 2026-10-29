package exporter

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"io"
	"net/http"
	"time"

	"github.com/Star-Trails/iloader-cert-export/locales"
	"golang.org/x/crypto/ocsp"
)

//go:embed assets/AppleWWDRCAG3.cer
var appleWWDRG3 []byte

// CheckStatus reports the local validity dates and, where the issuer answers, the
// revocation status. It follows ZSign's check in LiveContainer: the issuer is the
// bundled Apple WWDR CA that signed the certificate, not the operating system's
// trust store, which does not carry Apple's intermediates on Windows.
func CheckStatus(ctx context.Context, result Result) string {
	return checkStatus(ctx, result.certificate, nil, "")
}

func checkStatus(ctx context.Context, cert, issuer *x509.Certificate, ocspURL string) string {
	if cert == nil {
		return locales.CertUnknown()
	}
	now := time.Now()
	dates := locales.CertDates(cert.NotAfter.Local().Format("2006-01-02"))
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return locales.CertExpired(dates)
	}
	if issuer == nil {
		resolved, err := issuerFor(cert)
		if err != nil {
			return locales.CertUnverified(dates)
		}
		issuer = resolved
	}
	address := ocspURL
	if address == "" {
		if len(cert.OCSPServer) == 0 {
			return locales.CertUnverified(dates)
		}
		address = cert.OCSPServer[0]
	}
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return locales.CertUnverified(dates)
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(request))
	if err != nil {
		return locales.CertUnverified(dates)
	}
	httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	httpRequest.Header.Set("Accept", "application/ocsp-response")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(httpRequest)
	if err != nil {
		return locales.CertUnverified(dates)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		return locales.CertUnverified(dates)
	}
	// ParseResponseForCert verifies the signature by the issuer or by a responder it certified.
	status, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil || status.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return locales.CertUnverified(dates)
	}
	switch status.Status {
	case ocsp.Good:
		return locales.CertGood(dates)
	case ocsp.Revoked:
		return locales.CertRevoked(dates)
	default:
		return locales.CertUnverified(dates)
	}
}

// issuerFor returns the Apple CA that signed cert, from the embedded certificate or
// from the issuer named in the certificate's Authority Information Access extension.
func issuerFor(cert *x509.Certificate) (*x509.Certificate, error) {
	issued := func(candidate *x509.Certificate) bool {
		return candidate != nil && cert.CheckSignatureFrom(candidate) == nil
	}
	if ca, err := x509.ParseCertificate(appleWWDRG3); err == nil && issued(ca) {
		return ca, nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, address := range cert.IssuingCertificateURL {
		response, err := client.Get(address)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			continue
		}
		if ca, err := x509.ParseCertificate(body); err == nil && issued(ca) {
			return ca, nil
		}
	}
	return nil, errNoIssuer
}

type issuerError struct{}

func (issuerError) Error() string { return "issuer certificate not found" }

var errNoIssuer error = issuerError{}
