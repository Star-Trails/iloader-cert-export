# iloader-cert-export

A Windows app that exports the Apple Development certificate and private key already used by [iloader](https://github.com/nab138/iloader) as a password-protected `.p12` file. Import it into LiveContainer to set up JIT-less mode.

## Download and use

1. Download the Windows x64 ZIP from [Releases](https://github.com/Star-Trails/iloader-cert-export/releases) and extract it.
2. Open `iloader-cert-export.exe` using the same Windows account you use for iloader.
3. Select a saved iloader account, set a password for the exported file, choose a folder, and select **开始导出**. The interface is in Chinese.
4. Transfer the `.p12` to your device. In LiveContainer, select **Import Certificate**, choose the file, and enter the password. Check **JIT-Less Mode Diagnose** afterwards.

The app reads the existing private key from Windows Credential Manager or iloader's app-data directory, then matches it against certificates in locally saved provisioning profiles. Export is offline and does not sign in to Apple. If no matching certificate is available locally, first use iloader to sign an app.

After export, the app checks the certificate's validity dates and attempts an OCSP revocation check. This status check contacts the certificate issuer; it does not use your Apple account. A failed or unavailable check is reported as unknown. Keep the exported file and password private: the file contains your signing key.

## Build

The release build uses Go 1.27.3. From the project root:

```powershell
go test ./...
go run github.com/egoist/mygo/cmd/mygo@v0.7.3 build -platform windows/amd64
```

The [release workflow](.github/workflows/release.yml) builds the Windows app and creates the ZIP and SHA-256 checksum. [MyGo](https://github.com/egoist/mygo) provides the native interface. This project is not affiliated with iloader, LiveContainer or Apple.
