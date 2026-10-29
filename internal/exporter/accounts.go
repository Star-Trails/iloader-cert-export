package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Accounts returns iLoader's saved IDs in their saved order, retaining original
// spelling because Windows Credential Manager entries use the original email.
// It never reads or returns account passwords.
func (s *Service) Accounts(ctx context.Context) ([]Account, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return nil, errors.New("无法定位 iLoader 用户数据目录")
	}
	file, err := os.Open(filepath.Join(appdata, "me.nabdev.iloader", "data.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []Account{}, nil
	}
	if err != nil {
		return nil, errors.New("无法读取 iLoader 已保存账户")
	}
	defer file.Close()
	const maxSettingsBytes = 4 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(file, maxSettingsBytes+1))
	if err != nil || len(data) > maxSettingsBytes {
		return nil, errors.New("无法读取 iLoader 已保存账户")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var settings struct {
		IDs []string `json:"ids"`
	}
	if json.Unmarshal(data, &settings) != nil {
		return nil, errors.New("iLoader 账户列表格式无效")
	}
	accounts := make([]Account, 0, len(settings.IDs))
	seen := make(map[string]bool, len(settings.IDs))
	for _, id := range settings.IDs {
		id = strings.TrimSpace(id)
		key := strings.ToLower(id)
		if id != "" && !seen[key] {
			seen[key] = true
			accounts = append(accounts, Account{AppleID: id})
		}
	}
	return accounts, nil
}
