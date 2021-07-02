package forwardauth

import (
	"net"
)

func isIPInCIDRs(ip net.IP, cidrs []*net.IPNet) (trusted bool) {
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
