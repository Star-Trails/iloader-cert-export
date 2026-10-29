package main

import (
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/Star-Trails/iloader-cert-export/locales"
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
		ui.Text(c, locales.HeaderSubtitle()).Wrap().TextColor(t.TextMuted)
	})
	ui.Box(c).Absolute().Top(headerHeight-1).Left(0).Size(width, 1).Background(t.Border)
	ui.Scroll(c.Key("form-scroll")).Absolute().Top(headerHeight).Left(0).Size(width, max(0, height-headerHeight-footerHeight)).MinWidth(0).MinHeight(0).Padding(16, 24).Gap(16).Children(func() {
		if a.result != nil {
			a.resultView(c)
		}
		if a.errorText != "" {
			ui.Column(c).Gap(6).Children(func() {
				ui.Text(c, locales.ErrorDetails()).Bold().TextColor(t.Danger)
				ui.TextArea(c.Key("error-details"), &a.errorText).ReadOnly(true).Height(86).Label(locales.ErrorDetails()).TextColor(t.Danger)
			})
		}
		ui.Column(c).MinWidth(0).Gap(10).Children(func() {
			ui.Row(c).MinWidth(0).AlignItems(ui.Center).Gap(14).Children(func() {
				ui.Text(c, locales.AccountsHeading()).FontSize(17).Bold()
				if ui.Button(c.Key("refresh-accounts"), locales.RefreshAccounts()).Disabled(a.busy || a.loadingAccounts || a.picking).Clicked() {
					a.loadAccounts()
				}
			})
			if len(a.accounts) > 0 {
				ui.Field(c.Key("apple-id-field"), locales.SavedAccountLabel(), func() {
					ui.Select(c.Key("apple-id"), &a.appleID, a.accounts).Disabled(a.busy || a.loadingAccounts).MinWidth(0).FillWidth()
				}).Description(locales.SavedAccountHint())
			} else if a.loadingAccounts {
				ui.Text(c, locales.AccountsLoading()).TextColor(t.TextMuted)
			} else {
				ui.Text(c, locales.AccountsMissing()).Wrap().TextColor(t.TextMuted)
			}
		})
		ui.Box(c).Height(1).Background(t.Border)
		ui.Column(c).MinWidth(0).Gap(10).Children(func() {
			ui.Text(c, locales.ExportHeading()).FontSize(17).Bold()
			ui.Field(c.Key("p12-field"), locales.P12PasswordLabel(), func() {
				ui.TextInput(c.Key("p12-password"), &a.p12Password).Password().Disabled(a.busy).MinWidth(0).FillWidth()
			}).Description(locales.P12PasswordHint())
			ui.Field(c.Key("output-field"), locales.OutputLabel(), func() {
				ui.Column(c).MinWidth(0).Gap(8).Children(func() {
					ui.TextInput(c.Key("output-directory"), &a.outputDir).FillWidth().MinWidth(0).Placeholder(locales.OutputPlaceholder()).Disabled(a.busy || a.picking)
					if ui.Button(c.Key("choose-output"), locales.ChooseFolder()).Disabled(a.busy || a.picking).Clicked() {
						a.chooseOutput()
					}
				})
			})
		})
		ui.Text(c, locales.LocalFirstHint()).Wrap().FontSize(13).TextColor(t.TextMuted)
	})
	ui.Box(c).Absolute().Bottom(footerHeight).Left(0).Size(width, 1).Background(t.Border)
	a.statusView(c, width, footerHeight)
	a.twoFactorView(c)
}

func (a *application) statusView(c *ui.Context, width, height float32) {
	t := c.Theme()
	ui.Column(c).Absolute().Bottom(0).Left(0).Size(width, height).MinWidth(0).Background(t.Surface).Padding(12, 24).Gap(8).Children(func() {
		ui.Row(c).MinWidth(0).AlignItems(ui.Center).Gap(10).Children(func() {
			if a.busy || a.loadingAccounts {
				ui.Spinner(c).Size(18, 18).Label(locales.Busy())
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
				if ui.Button(c.Key("cancel-export"), locales.CancelExport()).Clicked() {
					a.cancelExport()
				}
			} else if ui.PrimaryButton(c.Key("start-export"), locales.StartExport()).Disabled(a.picking || a.loadingAccounts || len(a.accounts) == 0).Clicked() {
				a.startExport()
			}
		})
		ui.Text(c, a.message).Wrap().FontSize(13).TextColor(t.TextMuted)
		if a.errorText != "" {
			ui.Text(c, locales.ErrorFooterHint()).FontSize(13).TextColor(t.Danger)
		}
	})
}

func (a *application) resultView(c *ui.Context) {
	t := c.Theme()
	result := a.result
	ui.Column(c).Padding(18).Gap(12).Background(t.Surface).Border(1, t.Border).Radius(6).Children(func() {
		ui.Text(c, locales.SavedFiles()).FontSize(17).Bold().TextColor(t.Success)
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
			ui.Text(c, locales.TeamLabel(team)).Wrap().TextColor(t.TextMuted)
		}
		ui.Field(c, locales.P12Label(), func() {
			ui.TextInput(c.Key("result-p12"), &result.P12Path).ReadOnly(true)
		})
		if ui.Button(c.Key("reveal-export"), locales.RevealInFolder()).Clicked() {
			mygo.Shell.ShowItemInFolder(result.P12Path)
		}
	})
}

func (a *application) twoFactorView(c *ui.Context) {
	t := c.Theme()
	modal := ui.Modal(c.Key("two-factor-modal"), &a.showTwoFactor, func() {
		ui.Column(c).Gap(14).Children(func() {
			ui.Text(c, locales.TwoFactorTitle()).FontSize(21).Bold()
			ui.Text(c, locales.TwoFactorHint()).Wrap().TextColor(t.TextMuted)
			ui.Field(c, locales.TwoFactorLabel(), func() {
				if ui.TextInput(c.Key("two-factor-code"), &a.code).Placeholder(locales.TwoFactorPlaceholder()).AutoFocus().Submitted() {
					a.submitTwoFactor()
				}
			}).Error(a.codeError)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c.Key("cancel-two-factor"), locales.CancelExport()).Clicked() {
					a.cancelExport()
				}
				if ui.PrimaryButton(c.Key("submit-two-factor"), locales.VerifyAndContinue()).Clicked() {
					a.submitTwoFactor()
				}
			})
		})
	}).Width(420)
	if modal.Dismissed() && a.codeReply != nil {
		a.cancelExport()
	}
}

func stageTitle(stage string) string {
	switch stage {
	case "storage":
		return locales.StageStorage()
	case "saved_credentials":
		return locales.StageSavedCredentials()
	case "authenticating":
		return locales.StageAuthenticating()
	case "two_factor":
		return locales.StageTwoFactor()
	case "certificates":
		return locales.StageCertificates()
	case "writing":
		return locales.StageWriting()
	case "complete":
		return locales.StageComplete()
	default:
		return locales.StageDefault()
	}
}
