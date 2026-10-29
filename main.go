package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/i18n"
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

	stage     string
	busy      bool
	picking   bool
	cancel    context.CancelFunc
	status    statusKind
	message   messageKind
	errorText string
	result    *exporter.Result

	certificateStatus string

	languageTag string

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
	return &application{outputDir: output, status: statusReading, message: messageReading}
}

func main() {
	a := newApplication()
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
		if mygo.App.Locale() == a.systemLanguage() {
			a.languageTag = ""
		} else {
			a.languageTag = mygo.App.Locale()
		}
		a.loadAccounts()
	})
	if err := mygo.App.Run(); err != nil {
		log.Print("无法启动证书导出窗口：", err)
	}
}

// languageChoices lists the system default plus every language the catalogs ship,
// named in the app's current language for the default and in itself for the rest.
func (a *application) languageChoices() (tags, labels []string) {
	tags = append([]string{""}, mygo.App.Languages()...)
	labels = append(labels, locales.LanguageSystem())
	for _, tag := range tags[1:] {
		labels = append(labels, i18n.Autonym(tag))
	}
	return tags, labels
}

// systemLanguage is the language the app would show without a saved choice.
func (a *application) systemLanguage() string {
	languages := mygo.App.Languages()
	for _, preferred := range mygo.App.PreferredLanguages() {
		for _, tag := range languages {
			if i18n.Normalize(preferred) == i18n.Normalize(tag) ||
				strings.HasPrefix(i18n.Normalize(preferred), i18n.Normalize(tag)+"-") {
				return tag
			}
		}
	}
	if len(languages) > 0 {
		return languages[0]
	}
	return "en"
}

// setLanguage switches the whole app language and remembers the choice; "" follows the system.
func (a *application) setLanguage(tag string) {
	a.languageTag = tag
	mygo.App.SetLocale(tag)
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
	a.status = statusReading
	a.message = messageReading
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
				a.status = statusAccountsError
				a.message = messageAccountsError
				a.errorText = err.Error()
			case len(accountIDs) == 0:
				a.status = statusNoAccounts
				a.message = messageNoAccounts
			default:
				a.status = statusReady
				a.message = messageReady
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
	a.status = statusPreparing
	a.message = messageStarting
	go func() {
		defer cancel()
		service, err := exporter.New(exporter.Config{})
		var result exporter.Result
		if err == nil {
			result, err = service.Export(ctx, request, exporter.Callbacks{
				Progress: func(progress exporter.Progress) {
					a.update(func() {
						if ctx.Err() == nil {
							a.stage = progress.Stage
							a.status = statusStage
							a.message = messageNone
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
				a.status = statusDone
				a.message = messageDone
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
				a.status = statusCancelled
				a.message = messageCancelled
			default:
				a.status = statusFailed
				a.message = messageFailed
				a.errorText = err.Error()
			}
		})
	}()
}

func (a *application) cancelExport() {
	if a.cancel != nil {
		a.cancel()
		a.status = statusCancelling
		a.message = messageCancelling
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
		a.status = statusWaiting
		a.message = messageWaiting
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
		a.status = statusVerifying
		a.message = messageVerifying
	}
}
