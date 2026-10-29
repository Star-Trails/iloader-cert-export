# iloader-cert-export v1.0.0

Export the Apple Development identity iloader already uses as a password-protected `.p12` file on Windows x64, for importing into LiveContainer.

- Signs in with the account and password iloader saved, asks for a verification code when Apple requires one, and downloads the certificate matching the stored private key.
- Checks any local `.mobileprovision` first, but iloader does not normally leave one behind, so this is an edge case rather than the expected path.
- Checks validity dates after writing the file and attempts an OCSP revocation check; an unconfirmed answer is reported as unknown.
- Never creates, renews or revokes certificates, and leaves iloader storage unchanged.
- Interface in English, Simplified Chinese, Traditional Chinese and Japanese, following the Windows display language.

Prerequisites: iloader has signed an app under the same Windows user so the private key exists, its save-credentials option was enabled so step 2 can run unattended, and a trusted device is available for the verification code if Apple asks.

Download the ZIP, extract both executables to the same folder, and open `iloader-cert-export.exe`.
