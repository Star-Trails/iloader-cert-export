//go:build !windows

package exporter

import "errors"

func readCredential(string) ([]byte, error) {
	return nil, errors.New("Windows credential store unavailable")
}
