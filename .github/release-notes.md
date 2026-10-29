# iloader-cert-export v1.0.3

Export the Apple Development identity iloader already uses as a password-protected `.p12` file on Windows x64, for importing into LiveContainer.

- Signs in with the account and password iloader saved, asks for a verification code when Apple requires one, and downloads the certificate matching the stored private key. No device connection is involved.
- Checks validity dates after writing the file and asks the issuer's OCSP responder about revocation; an unconfirmed answer is reported as unknown.
- Never creates, renews or revokes certificates, and leaves iloader storage unchanged.
- Interface in English, Simplified Chinese, Traditional Chinese and Japanese, with a language selector in the header that is remembered between launches.
- Fixed the app starting in Simplified Chinese instead of following the Windows display language.
- Fixed the status bar and the language list keeping their previous language after switching.

**Set a strong, unique password for the file.** The `.p12` holds your signing key, and anyone with the file and its password can sign apps as your team until the certificate expires or is revoked. Keep the two apart and share neither.

Prerequisites: iloader has signed an app under the same Windows user with its save-credentials option enabled, and a trusted device is available if Apple asks for a verification code.

Download the ZIP, extract both executables to the same folder, and open `iloader-cert-export.exe`.
