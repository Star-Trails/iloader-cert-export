//go:build windows

package exporter

import "github.com/danieljoos/wincred"

func readCredential(entry string) ([]byte, error) {
	credential, err := wincred.GetGenericCredential(entry + ".iloader")
	if err != nil {
		return nil, err
	}
	return credential.CredentialBlob, nil
}
