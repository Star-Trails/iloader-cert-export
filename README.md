# iloader-cert-export

A Windows app that exports an existing [iloader](https://github.com/nab138/iloader) Apple Development identity as a password-protected `.p12` file, for importing into LiveContainer's JIT-less mode.

## Prerequisites

iloader keeps only the private key: it fetches the matching certificate from Apple at signing time and deletes the temporary signed app after installing, so nothing else is left behind. This tool therefore needs one local file that contains that certificate.

Put a `.mobileprovision` in `%APPDATA%\me.nabdev.iloader\` whose `DeveloperCertificates` entry matches the private key iloader saved for the selected account. A profile left there by an earlier iloader version or an earlier signing works; the app picks the matching certificate with the latest expiry and ignores profiles that match nothing.

To confirm the key exists, look for a Windows Credential Manager entry ending in `.iloader`, or `%APPDATA%\me.nabdev.iloader\<sha256 of the lowercased Apple ID>\key`.

If no matching profile is present, the app stops, leaves iloader untouched, and says so. It does not create, renew or revoke certificates.

## Download and use

1. Download the Windows x64 ZIP from [Releases](https://github.com/Star-Trails/iloader-cert-export/releases) and extract it.
2. Open `iloader-cert-export.exe` using the same Windows account you use for iloader.
3. Select a saved iloader account, set a password for the exported file, choose a folder, and select **开始导出**. The interface is in Chinese.
4. Transfer the `.p12` to your device. In LiveContainer, select **Import Certificate**, choose the file, and enter the password. Check **JIT-Less Mode Diagnose** afterwards.

Export itself is offline: no Apple sign-in, no device connection. After the file is written, the app checks the certificate's validity dates and tries an OCSP revocation check with the certificate issuer. That status check is the only network access, and an unavailable answer is reported as unknown.

Keep the exported file and its password private. The file contains your signing key.

## Build

Go 1.27.3, from the project root:

```powershell
go test ./...
go run github.com/egoist/mygo/cmd/mygo@v0.7.3 build -platform windows/amd64
```

The [release workflow](.github/workflows/release.yml) builds the Windows app and writes the ZIP plus a SHA-256 checksum. [MyGo](https://github.com/egoist/mygo) provides the native interface. This project is not affiliated with iloader, LiveContainer or Apple.
