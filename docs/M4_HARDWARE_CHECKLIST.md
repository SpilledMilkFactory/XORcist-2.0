# Windows 10/11 release acceptance worksheet

This is a **reusable blank checklist for future Windows releases**, not evidence that the published v2.0.0 release was untested. The maintainer reported successful fresh-VM validation for v2.0.0. For new releases, record separate evidence for **each** Windows version and retain it with the release qualification records.

| Field | Test observation |
| --- | --- |
| Physical hardware or VM, CPU architecture | Not recorded |
| Windows edition/build | Not recorded |
| Candidate artifact name and SHA-256 | Not recorded |
| Source Git SHA / release tag | Not recorded |
| Graphics driver and OpenGL version | Not recorded |
| Test date / tester | Not recorded |
| CLI startup, `--help` and diagnostic commands | Not recorded |
| GUI launch, tile dashboard, X/Escape, keyboard focus, DPI/font scaling | Not recorded |
| Interface, route, and DNS inspection | Not recorded |
| Base64, hex, file compare and XOR round trips | Not recorded |
| AES-256-GCM encrypt/decrypt byte-for-byte comparison | Not recorded |
| Wrong-password rejection without completed output | Not recorded |
| Windows imported-DLL inventory reviewed | Not recorded |
| Offline startup with no Visual Studio or missing DLLs | Not recorded |
| No-overwrite UX and useful error messages | Not recorded |
| Redacted screenshot evidence | Not recorded |
| Deviations, disposition and owner approval | Not recorded |

Unpack into a fresh directory and run without a developer toolchain. Do not work around missing DLLs by copying unspecified libraries; investigate and correct packaging instead. Test with non-sensitive data. Never commit passphrases, internal network addresses, or personal paths in public screenshots.
