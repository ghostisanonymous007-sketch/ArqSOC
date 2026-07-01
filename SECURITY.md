# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities by opening a private security advisory at
https://github.com/ghostisanonymous007-sketch/arqsoc/security/advisories/new.

Do **not** file public issues for security bugs.

## API Key Handling

- API keys are stored in `~/.arqsoc/config.json` with restricted file
  permissions (0600 on POSIX, owner-only ACL on Windows).
- Keys are never logged, printed, or included in command output.
- Environment variable overrides (`ARQSOC_VT_API_KEY`, etc.) are available
  for CI/CD pipelines -- ensure your pipeline masks these variables.
- CLI flag overrides (`--vt-key`, etc.) may appear in shell history. Use the
  config file or environment variables for persistent keys.

## Supported Versions

| Version | Supported |
|---|---|
| 1.x.x | Yes |
| < 1.0 | No |

## Scope

This project is a local analysis toolkit. It does not expose network services
or accept untrusted input over the network. Vulnerabilities in local file
parsing (e.g., malformed PE files, malicious YARA rules) are in scope.
