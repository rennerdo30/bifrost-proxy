//go:build darwin

package vpn

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <libproc.h>

// Get process name by PID
int get_proc_name(int pid, char *buf, int bufsize) {
    return proc_name(pid, buf, bufsize);
}

// Get process path by PID
int get_proc_path(int pid, char *buf, int bufsize) {
    return proc_pidpath(pid, buf, bufsize);
}
*/
import "C"

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

// darwinProcessLookup implements ProcessLookup for macOS.
type darwinProcessLookup struct{}

func newPlatformProcessLookup() ProcessLookup {
	return &darwinProcessLookup{}
}

// LookupBySocket finds the process for a socket on macOS.
// Uses lsof to find the process owning a socket.
func (d *darwinProcessLookup) LookupBySocket(local, remote netip.AddrPort, proto string) (*ProcessInfo, error) {
	// Use lsof to find the process
	// lsof -i proto@remote:port -sTCP:ESTABLISHED -nP
	var protoArg string
	switch proto {
	case "tcp":
		protoArg = "TCP"
	case "udp":
		protoArg = "UDP"
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}

	// Build the address filter
	var addrFilter string
	if remote.Addr().IsValid() && !remote.Addr().IsUnspecified() {
		addrFilter = fmt.Sprintf("%s@%s:%d", protoArg, remote.Addr(), remote.Port())
	} else {
		addrFilter = fmt.Sprintf("%s:%d", protoArg, local.Port())
	}

	// Run lsof
	cmd := exec.Command("lsof", "-i", addrFilter, "-nP", "-Fn")
	output, err := cmd.Output()
	if err != nil {
		// lsof returns 1 if no matches found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("lsof failed: %w", err)
	}

	// Parse lsof output
	// Output format with -F:
	// p<pid>
	// c<command>
	// n<name>
	return d.parseLsofOutput(output, local, remote)
}

// parseLsofOutput parses lsof -Fn output.
func (d *darwinProcessLookup) parseLsofOutput(output []byte, local, remote netip.AddrPort) (*ProcessInfo, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentPID int
	var currentName string

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		switch line[0] {
		case 'p':
			// Process ID
			pid, err := strconv.Atoi(line[1:])
			if err != nil {
				continue
			}
			currentPID = pid
		case 'c':
			// Command name
			currentName = line[1:]
		case 'n':
			// Network name (connection info)
			// Format: local->remote or *:port (LISTEN)
			connInfo := line[1:]

			// Check if this matches our connection
			if d.matchConnection(connInfo, local, remote) && currentPID > 0 {
				info := &ProcessInfo{
					PID:  currentPID,
					Name: currentName,
				}

				// Get full path using libproc
				info.Path = d.getProcessPath(currentPID)

				return info, nil
			}
		}
	}

	return nil, nil
}

// matchConnection checks if the lsof connection info matches our socket.
func (d *darwinProcessLookup) matchConnection(connInfo string, local, remote netip.AddrPort) bool {
	// Connection format: local->remote
	// Example: 192.168.1.1:12345->93.184.216.34:443

	parts := strings.Split(connInfo, "->")
	if len(parts) != 2 {
		return false
	}

	localPart := parts[0]
	remotePart := parts[1]

	// Parse local address
	localMatch := d.matchAddrPort(localPart, local)
	remoteMatch := d.matchAddrPort(remotePart, remote)

	return localMatch && remoteMatch
}

// matchAddrPort checks if a string matches an address:port.
func (d *darwinProcessLookup) matchAddrPort(s string, ap netip.AddrPort) bool {
	// Handle wildcards
	if strings.HasPrefix(s, "*:") {
		// Wildcard address, check port only
		portStr := s[2:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return false
		}
		return uint16(port) == ap.Port()
	}

	// Parse as address:port
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return false
	}

	addrStr := s[:lastColon]
	portStr := s[lastColon+1:]

	// Handle IPv6 brackets
	addrStr = strings.Trim(addrStr, "[]")

	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return false
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}

	return addr == ap.Addr() && uint16(port) == ap.Port()
}

// getProcessPath gets the executable path for a PID using libproc.
func (d *darwinProcessLookup) getProcessPath(pid int) string {
	buf := make([]byte, 4096)
	n := C.get_proc_path(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// getProcessName gets the process name for a PID using libproc.
func (d *darwinProcessLookup) getProcessName(pid int) string {
	buf := make([]byte, 256)
	n := C.get_proc_name(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}
