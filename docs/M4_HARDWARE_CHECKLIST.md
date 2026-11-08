# M4 — Windows 10 / Windows 11 Hardware Acceptance

Record a separate set of results for **each** supported Windows version.

| Field | Entry |
|---|---|
| Hardware / VM model and CPU architecture | Pending |
| Windows edition and OS build | Pending |
| Build artifact name and SHA-256 | Pending |
| Source Git SHA | Pending |
| Driver / OpenGL version | Pending |
| Test date and tester | Pending |
| CLI launch and --help output | Pending |
| GUI launch, tabs, keyboard focus, DPI/font check | Pending |
| Network inspection and DNS | Pending |
| Binary/Base64/hex round trip | Pending |
| Authenticated encrypt/decrypt byte-for-byte compare | Pending |
| Wrong passphrase correctly rejected without output | Pending |
| Windows DLL import list reviewed | Pending |
| Offline startup, no missing DLL error | Pending |
| No-overwrite UX + error-message clarity | Pending |
| Screenshots (with secrets/redacted identifiers) | Pending |
| Result, deviations and explicit sign-off | Pending |

Test extraction into a fresh directory and start without a development
build toolchain. If any DLL is missing, **fail** the candidate rather than
copying untracked dependencies. Do not confuse hosted GitHub Windows with a
real Windows 10/11 acceptance environment. Test with a non-sensitive fixture.
Never publish personal network interface addresses or secrets in screenshots.
