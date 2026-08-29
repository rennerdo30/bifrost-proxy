//go:build !windows

package sysproxy

import "time"

// commandTimeout bounds external command execution on the platforms that shell
// out to OS utilities (macOS networksetup, Linux gsettings). It lives in a
// !windows file because that is where its only users are; in the shared file it
// read as dead code on any Windows build.
const commandTimeout = 10 * time.Second
