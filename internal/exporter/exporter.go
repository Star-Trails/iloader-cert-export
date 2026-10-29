// Package exporter exports an existing iLoader signing identity through the bundled Windows helper.
package exporter

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Star-Trails/iloader-cert-export/locales"
)

type Config struct {
	// HelperPath overrides the bundled helper location. It is never resolved through PATH.
	HelperPath string
}

type Request struct {
	AppleID     string `json:"apple_id"`
	OutputDir   string `json:"output_dir"`
	P12Password string `json:"p12_password"`
}

type Account struct {
	AppleID string
}

type Progress struct {
	Stage   string
	Message string
}

type Callbacks struct {
	// Callbacks run on Export's goroutine; the UI must marshal updates onto its UI thread.
	Progress func(Progress)
	// TwoFactorCode must return when ctx is canceled. An error aborts the export.
	TwoFactorCode func(context.Context) (string, error)
}

type Result struct {
	P12Path        string `json:"p12_path"`
	TeamID         string `json:"team_id"`
	TeamName       string `json:"team_name"`
	CertificateDER string `json:"certificate_der"`

	certificate *x509.Certificate
}

type Service struct {
	helperPath string
}

func New(config Config) (*Service, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New(locales.ErrWindowsOnly())
	}
	path := config.HelperPath
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			return nil, errors.New(locales.ErrHelperDir())
		}
		path = filepath.Join(filepath.Dir(executable), "iloader-cert-helper.exe")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New(locales.ErrHelperPath())
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New(locales.ErrHelperMissing())
	}
	return &Service{helperPath: path}, nil
}

type event struct {
	Type   string `json:"type"`
	Stage  string `json:"stage"`
	Code   string `json:"code"`
	Result Result `json:"result"`
}

var progressMessages = map[string]func() string{
	"storage":           locales.StageStorage,
	"saved_credentials": locales.StageSavedCredentials,
	"authenticating":    locales.StageAuthenticating,
	"two_factor":        locales.StageTwoFactor,
	"certificates":      locales.StageCertificates,
	"writing":           locales.StageWriting,
	"complete":          locales.StageComplete,
}

var helperErrors = map[string]func() string{
	"invalid_request":   locales.ErrInvalidRequest,
	"storage":           locales.ErrStorage,
	"saved_credentials": locales.ErrSavedCredentials,
	"authentication":    locales.ErrAuthentication,
	"two_factor":        locales.ErrTwoFactor,
	"certificates":      locales.ErrCertificates,
	"no_match":          locales.ErrNoMatch,
	"encode":            locales.ErrEncode,
	"output":            locales.ErrOutput,
	"internal":          locales.ErrInternal,
}

// Export reads an existing identity; it never creates or revokes Apple certificates.
// P12 passwords and verification codes travel only over the helper's stdin pipe.
func (s *Service) Export(ctx context.Context, request Request, callbacks Callbacks) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	request.AppleID = strings.TrimSpace(request.AppleID)
	if request.AppleID == "" || request.P12Password == "" || request.OutputDir == "" {
		return Result{}, errors.New(helperErrors["invalid_request"]())
	}
	outputDir, err := filepath.Abs(request.OutputDir)
	if err != nil {
		return Result{}, errors.New(helperErrors["output"]())
	}
	info, err := os.Stat(outputDir)
	if err != nil || !info.IsDir() {
		return Result{}, errors.New(helperErrors["output"]())
	}
	request.OutputDir = outputDir

	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(processCtx, s.helperPath)
	configureCommand(cmd)
	// Never surface dependency diagnostics: Apple responses can contain account tokens.
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, errors.New(locales.ErrHelperComm())
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, errors.New(locales.ErrHelperComm())
	}
	if err := cmd.Start(); err != nil {
		return Result{}, errors.New(locales.ErrHelperStart())
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Wait()
		}
	}()
	encoder := json.NewEncoder(stdin)
	if err := encoder.Encode(request); err != nil {
		return Result{}, errors.New(locales.ErrHelperSend())
	}
	// Avoid retaining another copy of the P12 password through the rest of the operation.
	request.P12Password = ""

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	var result Result
	completed := false
	for scanner.Scan() {
		var message event
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			return Result{}, errors.New(locales.ErrHelperProtocol())
		}
		switch message.Type {
		case "progress":
			if text, ok := progressMessages[message.Stage]; ok && callbacks.Progress != nil {
				callbacks.Progress(Progress{Stage: message.Stage, Message: text()})
			}
		case "two_factor":
			if callbacks.TwoFactorCode == nil {
				return Result{}, errors.New(locales.ErrTwoFactorMissing())
			}
			code, err := callbacks.TwoFactorCode(processCtx)
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			if err != nil {
				return Result{}, errors.New(locales.ErrTwoFactorCancelled())
			}
			code = strings.TrimSpace(code)
			if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return Result{}, errors.New(locales.ErrTwoFactorFormat())
			}
			if err := encoder.Encode(struct {
				Type string `json:"type"`
				Code string `json:"code"`
			}{Type: "two_factor", Code: code}); err != nil {
				return Result{}, errors.New(locales.ErrHelperSendCode())
			}
		case "result":
			if completed || message.Result.P12Path == "" || filepath.Dir(message.Result.P12Path) != outputDir || filepath.Ext(message.Result.P12Path) != ".p12" {
				return Result{}, errors.New(locales.ErrHelperResult())
			}
			if decoded, err := base64.StdEncoding.DecodeString(message.Result.CertificateDER); err == nil {
				message.Result.certificate, _ = x509.ParseCertificate(decoded)
			}
			result, completed = message.Result, true
		case "error":
			if text, ok := helperErrors[message.Code]; ok {
				return Result{}, errors.New(text())
			}
			return Result{}, errors.New(locales.ErrInternal())
		default:
			return Result{}, errors.New(locales.ErrHelperProtocol())
		}
	}
	waitErr := cmd.Wait()
	waited = true
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if scanner.Err() != nil || waitErr != nil || !completed {
		return Result{}, errors.New(locales.ErrHelperExit())
	}
	return result, nil
}
