# M4 — GUI Usability and Accessibility Review

Review on Ubuntu 26.04 and both Windows 10/11 at 100%, 125% and 200% DPI
where available. Capture *redacted* screenshots of the main window and
important dialogs. Include evidence outside the repository if screenshots
contain private network addresses or file paths.

- All tabs visible or reachable, no clipped labels or unintelligible tooltips.
- Keyboard navigation, tab focus, password input masking, Escape/close,
  high-contrast text and predictable errors. Record shortcomings explicitly;
  Dear ImGui is not guaranteed equivalent to native screen-reader accessibility.
- Long DNS/probe operations do not stall repaint; no hidden security side
  effects; operation and network scope are described before executing.
- Secure-file operations cannot silently overwrite user data and distinguish
  wrong passwords from missing source files.
- Linux desktop icon/launcher and manpage install correctly; Windows extracts
  without admin rights or system-wide installer modifications.
- Preview and verify release screenshot evidence without secrets, personally
  identifiable network addresses, passwords or private directories.

This review is a release acceptance gate, not a claim that accessibility has
been independently certified.
