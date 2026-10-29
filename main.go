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

	busy              bool
	picking           bool
	cancel            context.CancelFunc
	status            string
	message           string
	errorText         string
	result            *exporter.Result
	certificateStatus string
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
			a.p12Password = ""
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
	a.status = "正在读取账户"
	a.message = "正在读取 iLoader 已保存的账户…"
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
				a.status = "无法读取账户"
				a.message = "请检查错误详情，然后刷新账户列表。"
				a.errorText = err.Error()
			case len(accountIDs) == 0:
				a.status = "未找到已保存的账户"
				a.message = "请确认以使用 iLoader 的同一 Windows 用户运行，再点击“刷新账户”。"
			default:
				a.status = "准备导出"
				a.message = "已读取 iLoader 账户。设置导出文件密码和保存位置后开始。"
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
			Parent: parent, Title: "选择证书保存文件夹", DefaultPath: initial,
			ButtonLabel: "选择此文件夹", Directory: true, CreateDirectories: true,
		})
		a.update(func() {
			a.picking = false
			if err != nil {
				a.errorText = "无法选择保存文件夹：" + err.Error()
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
		a.errorText = "请选择 iLoader 已保存的账户。"
	case a.p12Password == "":
		a.errorText = "请设置用于保护 .p12 文件的密码。"
	case strings.TrimSpace(a.outputDir) == "":
		a.errorText = "请选择或填写保存文件夹。"
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
	a.status = "正在准备"
	a.message = "正在启动导出，请稍候…"
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
			})
		}
		a.update(func() {
			a.busy = false
			a.cancel = nil
			a.p12Password = ""
			switch {
			case err == nil:
				a.result = &result
				a.status = "导出完成"
				a.message = "证书已保存。请妥善保管文件及导出密码。"
				a.certificateStatus = "正在检查证书状态…"
				go func() {
					status := exporter.CheckStatus(context.Background(), result)
					a.update(func() {
						if a.result != nil && a.result.P12Path == result.P12Path {
							a.certificateStatus = status
						}
					})
				}()
			case errors.Is(err, context.Canceled):
				a.status = "已取消"
				a.message = "导出已停止。再次导出时，请重新输入导出文件密码。"
			default:
				a.status = "导出失败"
				a.message = "请根据错误信息检查本地证书后重试。"
				a.errorText = err.Error()
			}
		})
	}()
}

func (a *application) cancelExport() {
	if a.cancel != nil {
		a.cancel()
		a.status = "正在取消"
		a.message = "正在停止导出，请稍候…"
	}
}
