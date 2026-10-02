// Package geo maps IP addresses to locations. The tracer never imports this;
// main wires it in, so you can swap ip-api.com for an offline GeoLite2
// database (or a fake in tests) without touching the networking code.
package geo

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Location is what we print next to each hop.
type Location struct {
	City, Region, Country string
	Org                   string // ISP / AS name, often more telling than city
	Lat, Lon              float64
}

func (l Location) String() string {
	parts := make([]string, 0, 3)
	for _, s := range []string{l.City, l.Region, l.Country} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "N/A"
	}
	s := strings.Join(parts, ", ")
	if l.Org != "" {
		s += " [" + l.Org + "]"
	}
	return s
}

// Locator looks up an IP. ok=false means "no data" (print N/A); err is for
// actual failures (network down, rate-limited).
type Locator interface {
	Lookup(ctx context.Context, ip net.IP) (loc Location, ok bool, err error)
}

// cgnat is RFC 6598 shared address space. net.IP.IsPrivate does NOT cover
// it, and ISP access networks use it, so we will see it in early hops.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// NonPublicReason returns a label if ip can never have a geo-location
// (private, CGNAT, loopback, link-local), else "".
func NonPublicReason(ip net.IP) string {
	switch {
	case ip.IsPrivate():
		return "private"
	case cgnat.Contains(ip):
		return "CGNAT"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsUnspecified():
		return "unspecified"
	}
	return ""
}

// Nop is a Locator that never knows anything. Use with -geo=none.
type Nop struct{}

func (Nop) Lookup(context.Context, net.IP) (Location, bool, error) {
	return Location{}, false, nil
}

// Describe is the one call main needs: handles non-public addresses,
// lookup failures and missing data uniformly.
func Describe(ctx context.Context, l Locator, ip net.IP) string {
	if r := NonPublicReason(ip); r != "" {
		return fmt.Sprintf("N/A (%s)", r)
	}
	loc, ok, err := l.Lookup(ctx, ip)
	if err != nil {
		return "N/A (lookup failed)"
	}
	if !ok {
		return "N/A"
	}
	return loc.String()
}