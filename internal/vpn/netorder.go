package vpn

// portToNetworkOrder converts a host-order TCP/UDP port to the network-byte-
// order 16-bit value that Windows' MIB connection tables store in the low word
// of a DWORD, widened for comparison against those DWORD fields.
//
// The byte swap must happen in 16-bit arithmetic. The previous inline form
// widened to uint32 BEFORE shifting — `uint32(port)<<8 | uint32(port)>>8` —
// which pushed the port's high byte into bits 16–23 instead of wrapping it
// into the low byte, so the computed value never matched a real table entry
// (port 443 = 0x01BB should become 0xBB01; the widened form produced 0x1BB01).
// Every per-app split-tunnel socket lookup on Windows failed because of it.
func portToNetworkOrder(port uint16) uint32 {
	return uint32(port>>8 | port<<8)
}
