// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"sync"
)

var (
	gatewayOnce sync.Once
	gatewayIP   net.IP
)

// defaultGateway returns the IPv4 default gateway on Linux, or nil. Inside a
// Docker container this is the host, which is where connections to a port
// published on the host's 127.0.0.1 appear to come from.
func defaultGateway() net.IP {
	gatewayOnce.Do(func() { gatewayIP = readGateway("/proc/net/route") })
	return gatewayIP
}

func readGateway(path string) net.IP {
	f, err := os.Open(path) //nolint:gosec // fixed system path
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags ...; the default route has destination 0.
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.LittleEndian.Uint32(b))
		if !ip.IsUnspecified() {
			return ip
		}
	}
	return nil
}
