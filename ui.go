package main

import (
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

var exportTheme = func() *ui.Theme {
	t := ui.LightTheme()
	t.Background = ui.Hex("#FFFFFF")
	t.Surface = ui.Hex("#FFFFFF")
	t.SurfaceHover = ui.Hex("#F4F5F6")
	t.SurfacePressed = ui.Hex("#E8EAED")
	t.Border = ui.Hex("#E2E5E9")
	t.Text = ui.Hex("#20334A")
	t.TextMuted = ui.Hex("#65778C")
	t.Accent = ui.Hex("#244A7D")
	t.AccentHover = ui.Hex("#1D3E6B")
	t.AccentPressed = ui.Hex("#173359")
	t.Success = ui.Hex("#11776D")
	t.Selection = ui.RGBA(36, 74, 125, 0.18)
	t.Focus = ui.RGBA(36, 74, 125, 0.55)
	t.Radius = 6
	t.FontSize = 14
	if runtime.GOOS == "windows" {
		t.Font = "Microsoft YaHei UI"
	}
	return t
}()

func (a *application) view(c *ui.Context) {
	a.invalidate = c.Invalidate
	c.SetTheme(exportTheme)
	t := c.Theme()
	width, height := c.Size()
	const headerHeight, footerHeight = float32(102), float32(128)
	c.Root().Clip()
	ui.Column(c).Absolute().Top(0).Left(0).Size(width, headerHeight).Padding(16, 24).Gap(6).Children(func() {
		ui.Text(c, "iloader-cert-export").FontSize(24).Bold()
		ui.Text(c, "使用 iLoader 已保存的账户，导出用于 LiveContainer 的 .p12 签名证书。").Wrap().TextColor(t.TextMuted)
	})
	ui.Box(c).Absolute().Top(headerHeight-1).Left(0).Size(width, 1).Background(t.Border)
	ui.Scroll(c.Key("form-scroll")).Absolute().Top(headerHeight).Left(0).Size(width, max(0, height-headerHeight-footerHeight)).MinWidth(0).MinHeight(0).Padding(16, 24).Gap(16).Children(func() {
		if a.result != nil {
			a.resultView(c)
		}
		if a.errorText != "" {
			ui.Column(c).Gap(6).Children(func() {
				ui.Text(c, "错误详情").Bold().TextColor(t.Danger)
				ui.TextArea(c.Key("error-details"), &a.errorText).ReadOnly(true).Height(86).Label("错误详情").TextColor(t.Danger)
			})
		}
		ui.Column(c).MinWidth(0).Gap(10).Children(func() {
			ui.Row(c).MinWidth(0).AlignItems(ui.Center).Gap(14).Children(func() {
				ui.Text(c, "iLoader 账户").FontSize(17).Bold()
				if ui.Button(c.Key("refresh-accounts"), "刷新账户").Disabled(a.busy || a.loadingAccounts || a.picking).Clicked() {
					a.loadAccounts()
				}
			})
			if len(a.accounts) > 0 {
				ui.Field(c.Key("apple-id-field"), "已保存的 Apple 账户", func() {
					ui.Select(c.Key("apple-id"), &a.appleID, a.accounts).Disabled(a.busy || a.loadingAccounts).MinWidth(0).FillWidth()
				}).Description("直接使用 iLoader 已保存的账户。")
			} else if a.loadingAccounts {
				ui.Text(c, "正在读取已保存的账户…").TextColor(t.TextMuted)
			} else {
				ui.Text(c, "未找到 iLoader 已保存的账户。确认使用同一 Windows 用户后，点击“刷新账户”。").Wrap().TextColor(t.TextMuted)
			}
		})
		ui.Box(c).Height(1).Background(t.Border)
		ui.Column(c).MinWidth(0).Gap(10).Children(func() {
			ui.Text(c, "导出设置").FontSize(17).Bold()
			ui.Field(c.Key("p12-field"), "导出文件密码", func() {
				ui.TextInput(c.Key("p12-password"), &a.p12Password).Password().Disabled(a.busy).MinWidth(0).FillWidth()
			}).Description("导入证书时需要使用，请记住此密码。")
			ui.Field(c.Key("output-field"), "保存文件夹", func() {
				ui.Column(c).MinWidth(0).Gap(8).Children(func() {
					ui.TextInput(c.Key("output-directory"), &a.outputDir).FillWidth().MinWidth(0).Placeholder("选择或填写文件夹路径").Disabled(a.busy || a.picking)
					if ui.Button(c.Key("choose-output"), "选择文件夹").Disabled(a.busy || a.picking).Clicked() {
						a.chooseOutput()
					}
				})
			})
		})
		ui.Text(c, "从本机 iLoader 数据导出，完成后自动检查证书状态。").Wrap().FontSize(13).TextColor(t.TextMuted)
	})
	ui.Box(c).Absolute().Bottom(footerHeight).Left(0).Size(width, 1).Background(t.Border)
	a.statusView(c, width, footerHeight)
}

func (a *application) statusView(c *ui.Context, width, height float32) {
	t := c.Theme()
	ui.Column(c).Absolute().Bottom(0).Left(0).Size(width, height).MinWidth(0).Background(t.Surface).Padding(12, 24).Gap(8).Children(func() {
		ui.Row(c).MinWidth(0).AlignItems(ui.Center).Gap(10).Children(func() {
			if a.busy || a.loadingAccounts {
				ui.Spinner(c).Size(18, 18).Label("正在处理")
			} else {
				color := t.TextMuted
				if a.result != nil {
					color = t.Success
				} else if a.errorText != "" {
					color = t.Danger
				}
				ui.Box(c).Size(8, 8).Radius(4).Background(color)
			}
			ui.Text(c, a.status).MinWidth(0).Grow(1).Bold()
			if a.busy {
				if ui.Button(c.Key("cancel-export"), "取消导出").Clicked() {
					a.cancelExport()
				}
			} else if ui.PrimaryButton(c.Key("start-export"), "开始导出").Disabled(a.picking || a.loadingAccounts || len(a.accounts) == 0).Clicked() {
				a.startExport()
			}
		})
		ui.Text(c, a.message).Wrap().FontSize(13).TextColor(t.TextMuted)
		if a.errorText != "" {
			ui.Text(c, "操作未完成，请查看上方错误详情。").FontSize(13).TextColor(t.Danger)
		}
	})
}

func (a *application) resultView(c *ui.Context) {
	t := c.Theme()
	result := a.result
	ui.Column(c).Padding(18).Gap(12).Background(t.Surface).Border(1, t.Border).Radius(6).Children(func() {
		ui.Text(c, "已保存的文件").FontSize(17).Bold().TextColor(t.Success)
		ui.Text(c, a.certificateStatus).Wrap().FontSize(13).TextColor(t.TextMuted)
		if result.TeamName != "" || result.TeamID != "" {
			team := result.TeamName
			if result.TeamID != "" {
				if team != "" {
					team += "（" + result.TeamID + "）"
				} else {
					team = result.TeamID
				}
			}
			ui.Text(c, "开发者团队："+team).Wrap().TextColor(t.TextMuted)
		}
		ui.Field(c, "P12 证书", func() {
			ui.TextInput(c.Key("result-p12"), &result.P12Path).ReadOnly(true)
		})
		if ui.Button(c.Key("reveal-export"), "在文件夹中显示").Clicked() {
			mygo.Shell.ShowItemInFolder(result.P12Path)
		}
	})
}

func stageTitle(stage string) string {
	switch stage {
	case "storage":
		return "正在准备保存位置"
	case "local_profiles":
		return "正在查找本地证书"
	case "writing":
		return "正在保存文件"
	case "complete":
		return "正在完成导出"
	default:
		return "正在导出"
	}
}
