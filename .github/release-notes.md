# iloader-cert-export v1.0.0

Export an existing iloader Apple Development identity to a password-protected `.p12` file on Windows x64, for importing into LiveContainer.

Requires a `.mobileprovision` in `%APPDATA%\me.nabdev.iloader\` whose `DeveloperCertificates` contains the certificate for the private key iloader saved. Current iloader keeps only the private key and deletes the temporary signed app after installing, so offline export cannot recover a certificate that is not in such a profile.

- Reads saved iloader accounts and the stored private key without signing in to Apple.
- Picks the matching certificate with the latest expiry; ignores profiles that match nothing.
- Checks validity dates after export and attempts an OCSP revocation check. An unavailable check is reported as unknown.
- Never creates, renews or revokes certificates, and leaves iloader storage unchanged.

Download the ZIP, extract it, and open `iloader-cert-export.exe`. The interface is in Chinese.
