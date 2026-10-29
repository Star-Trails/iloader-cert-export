package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/Star-Trails/iloader-cert-export/locales"

	"github.com/Star-Trails/iloader-cert-export/internal/exporter"
)

// All application state is owned by the UI thread. Export callbacks marshal
// changes through update, so the native view never races the background work.
type application struct {
	window     *mygo.Window
	invalidate func()
	closed     bool

	appleID         string
	accounts        []string
	loadingAccounts bool
	p12Password     string
	outputDir       string

	busy      bool
	picking   bool
	cancel    context.CancelFunc
	status    string
	message   string
	errorText string
	result    *exporter.Result

	certificateStatus string

	showTwoFactor bool
	code          string
	codeError     string
	codeReply     chan string
}

func newApplication() *application {
	output := ""
	if home, err := os.UserHomeDir(); err == nil {
		output = filepath.Clean(home)
	}
	return &application{outputDir: output, status: "正在读取账户", message: "正在读取 iLoader 已保存的账户…"}
}

func main() {
	a := newApplication()
	mygo.App.SetLocale("zh-Hans")
	mygo.App.WhenReady(func() {
		a.window = mygo.NewWindow(mygo.WindowOptions{
			Title:           "iloader-cert-export",
			Width:           760,
			Height:          820,
			MinWidth:        540,
			MinHeight:       600,
			BackgroundColor: "#FFFFFF",
			Content:         ui.View(a.view),
		})
		a.window.OnClosed(func() {
			a.closed = true
			if a.cancel != nil {
				a.cancel()
			}
			a.p12Password, a.code = "", ""
		})
		a.loadAccounts()
	})
	if err := mygo.App.Run(); err != nil {
		log.Print("无法启动证书导出窗口：", err)
	}
}

func (a *application) update(fn func()) {
	mygo.RunOnMain(func() {
		if a.closed {
			return
		}
		fn()
		if a.invalidate != nil {
			a.invalidate()
		}
	})
}

func (a *application) loadAccounts() {
	if a.busy || a.loadingAccounts || a.picking {
		return
	}
	a.loadingAccounts = true
	a.errorText = ""
	a.status = locales.StatusReadingAccounts()
	a.message = locales.MessageReadingAccounts()
	previous := a.appleID
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go func() {
		defer cancel()
		service, err := exporter.New(exporter.Config{})
		var accounts []exporter.Account
		if err == nil {
			accounts, err = service.Accounts(ctx)
		}
		accountIDs := make([]string, 0, len(accounts))
		for _, account := range accounts {
			if account.AppleID != "" {
				accountIDs = append(accountIDs, account.AppleID)
			}
		}
		a.update(func() {
			a.loadingAccounts = false
			a.cancel = nil
			a.accounts = accountIDs
			a.appleID = ""
			for _, id := range accountIDs {
				if id == previous {
					a.appleID = id
					break
				}
			}
			if a.appleID == "" && len(accountIDs) > 0 {
				a.appleID = accountIDs[0]
			}
			switch {
			case err != nil:
				a.status = locales.StatusAccountsError()
				a.message = locales.MessageAccountsErrorHint()
				a.errorText = err.Error()
			case len(accountIDs) == 0:
				a.status = locales.StatusNoAccounts()
				a.message = locales.MessageNoAccountsHint()
			default:
				a.status = locales.StatusReady()
				a.message = locales.MessageReadyHint()
			}
		})
	}()
}

func (a *application) chooseOutput() {
	if a.busy || a.picking {
		return
	}
	a.picking = true
	parent, initial := a.window, a.outputDir
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: parent, Title: locales.ChooseFolderTitle(), DefaultPath: initial,
			ButtonLabel: locales.ChooseFolderButton(), Directory: true, CreateDirectories: true,
		})
		a.update(func() {
			a.picking = false
			if err != nil {
				a.errorText = locales.ChooseFolderFailed(err.Error())
			} else if len(paths) > 0 {
				a.outputDir = paths[0]
				a.errorText = ""
			}
		})
	}()
}

func (a *application) startExport() {
	if a.busy || a.picking || a.loadingAccounts {
		return
	}
	a.errorText = ""
	a.result = nil
	switch {
	case a.appleID == "":
		a.errorText = locales.ValidationAccount()
	case a.p12Password == "":
		a.errorText = locales.ValidationPassword()
	case strings.TrimSpace(a.outputDir) == "":
		a.errorText = locales.ValidationOutput()
	}
	if a.errorText != "" {
		return
	}

	request := exporter.Request{
		AppleID:     a.appleID,
		P12Password: a.p12Password, OutputDir: strings.TrimSpace(a.outputDir),
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.busy = true
	a.status = locales.StatusPreparing()
	a.message = locales.MessageStarting()
	go func() {
		defer cancel()
		service, err := exporter.New(exporter.Config{})
		var result exporter.Result
		if err == nil {
			result, err = service.Export(ctx, request, exporter.Callbacks{
				Progress: func(progress exporter.Progress) {
					a.update(func() {
						if ctx.Err() == nil {
							a.status = stageTitle(progress.Stage)
							a.message = progress.Message
						}
					})
				},
				TwoFactorCode: a.requestTwoFactor,
			})
		}
		a.update(func() {
			a.busy = false
			a.cancel = nil
			a.showTwoFactor = false
			a.codeReply = nil
			a.p12Password, a.code = "", ""
			switch {
			case err == nil:
				a.result = &result
				a.status = locales.StatusDone()
				a.message = locales.MessageDone()
				a.certificateStatus = locales.CertChecking()
				go func() {
					status := exporter.CheckStatus(context.Background(), result)
					a.update(func() {
						if a.result != nil && a.result.P12Path == result.P12Path {
							a.certificateStatus = status
						}
					})
				}()
			case errors.Is(err, context.Canceled):
				a.status = locales.StatusCancelled()
				a.message = locales.MessageCancelled()
			default:
				a.status = locales.StatusFailed()
				a.message = locales.MessageFailedHint()
				a.errorText = err.Error()
			}
		})
	}()
}

func (a *application) cancelExport() {
	if a.cancel != nil {
		a.cancel()
		a.status = locales.StatusCancelling()
		a.message = locales.MessageCancelling()
	}
	a.showTwoFactor = false
	a.codeReply = nil
	a.code = ""
}

func (a *application) requestTwoFactor(ctx context.Context) (string, error) {
	reply := make(chan string, 1)
	a.update(func() {
		if ctx.Err() != nil {
			return
		}
		a.code, a.codeError = "", ""
		a.codeReply = reply
		a.showTwoFactor = true
		a.status = locales.StatusWaiting()
		a.message = locales.MessageWaiting()
	})
	defer a.update(func() {
		if a.codeReply == reply {
			a.showTwoFactor = false
			a.codeReply = nil
			a.code = ""
		}
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case code := <-reply:
		return code, nil
	}
}

func (a *application) submitTwoFactor() {
	code := strings.TrimSpace(a.code)
	valid := len(code) == 6
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			valid = false
		}
	}
	if !valid {
		a.codeError = locales.TwoFactorInvalid()
		return
	}
	if a.codeReply != nil {
		a.codeReply <- code
		a.codeReply = nil
		a.showTwoFactor = false
		a.code = ""
		a.status = locales.StatusVerifying()
		a.message = locales.MessageVerifying()
	}
}
