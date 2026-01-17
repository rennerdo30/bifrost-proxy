//go:build linux

package vpn

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// linuxProcessLookup implements ProcessLookup for Linux.
type linuxProcessLookup struct{}

func newPlatformProcessLookup() ProcessLookup {
	return &linuxProcessLookup{}
}

// LookupBySocket finds the process for a socket on Linux.
// It reads /proc/net/tcp and /proc/net/udp to find the socket,
// then walks /proc/*/fd to find the owning process.
func (l *linuxProcessLookup) LookupBySocket(local, remote netip.AddrPort, proto string) (*ProcessInfo, error) {
	// Determine which /proc/net file to read
	var netFile string
	switch proto {
	case "tcp":
		if local.Addr().Is6() {
			netFile = "/proc/net/tcp6"
		} else {
			netFile = "/proc/net/tcp"
		}
	case "udp":
		if local.Addr().Is6() {
			netFile = "/proc/net/udp6"
		} else {
			netFile = "/proc/net/udp"
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}

	// Find the inode for this socket
	inode, err := l.findSocketInode(netFile, local, remote)
	if err != nil {
		return nil, err
	}
	if inode == 0 {
		return nil, nil // Socket not found
	}

	// Find the process owning this inode
	return l.findProcessByInode(inode)
}

// findSocketInode finds the inode for a socket in /proc/net/*.
func (l *linuxProcessLookup) findSocketInode(netFile string, local, remote netip.AddrPort) (uint64, error) {
	file, err := os.Open(netFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	localHex := addrPortToHex(local)
	remoteHex := addrPortToHex(remote)

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header line

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Fields: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
		localAddr := strings.ToLower(fields[1])
		remoteAddr := strings.ToLower(fields[2])

		if localAddr == localHex && remoteAddr == remoteHex {
			// Found it, parse inode
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				continue
			}
			return inode, nil
		}
	}

	return 0, scanner.Err()
}

// addrPortToHex converts an address:port to the hex format used in /proc/net/*.
func addrPortToHex(ap netip.AddrPort) string {
	addr := ap.Addr()
	port := ap.Port()

	var addrHex string
	if addr.Is4() {
		// IPv4: bytes reversed, then hex
		a4 := addr.As4()
		addrHex = fmt.Sprintf("%02X%02X%02X%02X", a4[3], a4[2], a4[1], a4[0])
	} else {
		// IPv6: each 32-bit word reversed
		a16 := addr.As16()
		addrHex = fmt.Sprintf("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			a16[3], a16[2], a16[1], a16[0],
			a16[7], a16[6], a16[5], a16[4],
			a16[11], a16[10], a16[9], a16[8],
			a16[15], a16[14], a16[13], a16[12])
	}

	portHex := fmt.Sprintf("%04X", port)
	return strings.ToLower(addrHex + ":" + portHex)
}

// findProcessByInode finds the process owning a socket inode.
func (l *linuxProcessLookup) findProcessByInode(inode uint64) (*ProcessInfo, error) {
	socketLink := fmt.Sprintf("socket:[%d]", inode)

	// Walk /proc/*/fd
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		// Check if it's a PID directory
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		// Check fd directory
		fdDir := filepath.Join("/proc", entry, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}

			if link == socketLink {
				// Found the process, get its info
				return l.getProcessInfo(pid)
			}
		}
	}

	return nil, nil
}

// getProcessInfo reads process information from /proc.
func (l *linuxProcessLookup) getProcessInfo(pid int) (*ProcessInfo, error) {
	info := &ProcessInfo{PID: pid}

	// Read process name from /proc/PID/comm
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	if data, err := os.ReadFile(commPath); err == nil {
		info.Name = strings.TrimSpace(string(data))
	}

	// Read executable path from /proc/PID/exe
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if path, err := os.Readlink(exePath); err == nil {
		info.Path = path
	}

	// If name is empty, try to get from cmdline
	if info.Name == "" {
		cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
		if data, err := os.ReadFile(cmdlinePath); err == nil {
			// cmdline is null-separated
			parts := strings.Split(string(data), "\x00")
			if len(parts) > 0 && parts[0] != "" {
				info.Name = filepath.Base(parts[0])
			}
		}
	}

	return info, nil
}

// hexToAddr converts a hex address from /proc/net/* to netip.Addr.
func hexToAddr(hexStr string) (netip.Addr, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return netip.Addr{}, err
	}

	if len(data) == 4 {
		// IPv4: reverse bytes
		return netip.AddrFrom4([4]byte{data[3], data[2], data[1], data[0]}), nil
	} else if len(data) == 16 {
		// IPv6: reverse each 32-bit word
		var addr [16]byte
		for i := 0; i < 4; i++ {
			addr[i*4+0] = data[i*4+3]
			addr[i*4+1] = data[i*4+2]
			addr[i*4+2] = data[i*4+1]
			addr[i*4+3] = data[i*4+0]
		}
		return netip.AddrFrom16(addr), nil
	}

	return netip.Addr{}, fmt.Errorf("invalid address length: %d", len(data))
}
