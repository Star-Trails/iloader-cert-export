package exporter

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CheckStatus checks the local validity dates and, where possible, the issuer's OCSP response.
// A network failure or an untrusted issuer never becomes a valid status.
func CheckStatus(ctx context.Context, result Result) string {
	return checkStatus(ctx, result, nil)
}

func checkStatus(ctx context.Context, result Result, roots *x509.CertPool) string {
	cert := result.certificate
	if cert == nil {
		return "证书状态：未知"
	}
	now := time.Now()
	dates := fmt.Sprintf("有效期至 %s", cert.NotAfter.Local().Format("2006-01-02 15:04"))
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "证书已过期或尚未生效；" + dates
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	candidates := append([]*x509.Certificate(nil), result.issuers...)
	for _, address := range cert.IssuingCertificateURL {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		issuer, err := x509.ParseCertificate(body)
		if err == nil {
			candidates = append(candidates, issuer)
		}
	}
	for _, issuer := range candidates {
		if cert.CheckSignatureFrom(issuer) != nil {
			continue
		}
		// Only accept an issuer rooted in the operating system trust store.
		intermediates := x509.NewCertPool()
		for _, candidate := range candidates {
			intermediates.AddCert(candidate)
		}
		if _, err := issuer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			continue
		}
		request, err := ocsp.CreateRequest(cert, issuer, nil)
		if err != nil {
			continue
		}
		for _, address := range cert.OCSPServer {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(request))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/ocsp-request")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				continue
			}
			status, err := ocsp.ParseResponseForCert(body, cert, issuer)
			if err != nil || status.ThisUpdate.After(now.Add(5*time.Minute)) || status.NextUpdate.IsZero() || !status.NextUpdate.After(now) {
				continue
			}
			switch status.Status {
			case ocsp.Good:
				return "证书状态：有效；" + dates
			case ocsp.Revoked:
				return "证书状态：已吊销；" + dates
			}
		}
	}
	return "证书状态：未知（未能确认吊销状态）；" + dates
}
