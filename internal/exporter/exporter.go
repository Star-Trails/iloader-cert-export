// Package exporter exports existing iLoader signing identities without network access.
package exporter

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

type Config struct{}
type Service struct{}
type Request struct{ AppleID, OutputDir, P12Password string }
type Account struct{ AppleID string }
type Progress struct{ Stage, Message string }
type Callbacks struct{ Progress func(Progress) }
type Result struct {
	P12Path, TeamID, TeamName string
	certificate               *x509.Certificate
	issuers                   []*x509.Certificate
}

func New(Config) (*Service, error) { return &Service{}, nil }

type profile struct {
	TeamIdentifier        []string `plist:"TeamIdentifier"`
	TeamName              string   `plist:"TeamName"`
	DeveloperCertificates [][]byte `plist:"DeveloperCertificates"`
	issuers               []*x509.Certificate
}

func matchingCertificate(dir string, key *rsa.PrivateKey, now time.Time) (*x509.Certificate, profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, profile{}, err
	}
	var best *x509.Certificate
	var selected profile
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".mobileprovision") {
			continue
		}
		file := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil || info.Size() > 32*1024*1024 {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		signed, err := pkcs7.Parse(data)
		if err != nil {
			continue
		}
		var p profile
		if _, err := plist.Unmarshal(signed.Content, &p); err != nil {
			continue
		}
		p.issuers = signed.Certificates
		for _, encoded := range p.DeveloperCertificates {
			cert, err := x509.ParseCertificate(encoded)
			if err != nil {
				continue
			}
			public, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok || !public.Equal(&key.PublicKey) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				continue
			}
			if best == nil || cert.NotAfter.After(best.NotAfter) {
				best, selected = cert, p
			}
		}
	}
	return best, selected, nil
}

// Export only reads iLoader storage; it does not contact Apple or change certificates.
func (s *Service) Export(ctx context.Context, request Request, callbacks Callbacks) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	id := strings.TrimSpace(request.AppleID)
	if id == "" || request.OutputDir == "" || request.P12Password == "" {
		return Result{}, errors.New("请选择账户、输出文件夹并设置导出密码")
	}
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return Result{}, errors.New("无法定位 iLoader 用户数据目录")
	}
	dir := filepath.Join(appdata, "me.nabdev.iloader")
	if callbacks.Progress != nil {
		callbacks.Progress(Progress{"storage", "正在读取 iLoader 已有私钥…"})
	}
	digest := sha256.Sum256([]byte(strings.ToLower(id)))
	entry := hex.EncodeToString(digest[:]) + "/key"
	data, err := readCredential(entry)
	if err != nil {
		data, err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(entry)))
	}
	if err != nil {
		return Result{}, errors.New("未找到此账户的 iLoader 私钥")
	}
	defer clear(data)
	parsed, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return Result{}, errors.New("无法读取 iLoader 私钥")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return Result{}, errors.New("iLoader 私钥格式不受支持")
	}
	if callbacks.Progress != nil {
		callbacks.Progress(Progress{"local_profiles", "正在查找匹配的本地证书…"})
	}
	cert, p, err := matchingCertificate(dir, key, time.Now())
	if err != nil {
		return Result{}, errors.New("无法读取 iLoader 的本地描述文件")
	}
	if cert == nil {
		return Result{}, errors.New("本地描述文件中没有与此私钥匹配且未过期的证书；请先使用 iLoader 签名应用")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if callbacks.Progress != nil {
		callbacks.Progress(Progress{"writing", "正在加密并保存 P12 文件…"})
	}
	encoded, err := pkcs12.Modern2023.Encode(key, cert, nil, request.P12Password)
	if err != nil {
		return Result{}, errors.New("无法生成 P12 文件")
	}
	defer clear(encoded)
	dirout, err := filepath.Abs(request.OutputDir)
	if err != nil {
		return Result{}, errors.New("输出文件夹无效")
	}
	for n := range 10000 {
		name := "iloader-certificate.p12"
		if n > 0 {
			name = fmt.Sprintf("iloader-certificate-%d.p12", n)
		}
		path := filepath.Join(dirout, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return Result{}, errors.New("无法保存 P12，请检查输出文件夹权限")
		}
		_, writeErr := f.Write(encoded)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return Result{}, errors.New("无法保存完整的 P12 文件")
		}
		result := Result{P12Path: path, TeamName: p.TeamName, certificate: cert, issuers: p.issuers}
		if len(p.TeamIdentifier) > 0 {
			result.TeamID = p.TeamIdentifier[0]
		}
		return result, nil
	}
	return Result{}, errors.New("无法创建 P12 文件：同名文件过多")
}
