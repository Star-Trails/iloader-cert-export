# iloader-cert-export v1.0.0

Export an existing iloader signing certificate and private key to a password-protected `.p12` file on Windows x64.

- Reads saved iloader accounts and matches local provisioning profiles without signing in to Apple.
- Checks certificate validity dates and attempts an OCSP revocation check after export. An unavailable check is shown as unknown.
- Leaves existing certificates and iloader storage unchanged.

Download the ZIP, extract it, and open `iloader-cert-export.exe`. The interface is in Chinese.
