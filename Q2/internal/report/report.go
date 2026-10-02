// Package report formats tracer results. Kept separate so output tweaks
// (e.g. matching the assignment's sample format) never touch socket code.
package report

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"geotrace/internal/tracer"
)

/// Header prints the traceroute-style banner.
func Header(w io.Writer, cfg tracer.Config) {
	fmt.Fprintf(w, "geotrace to %s (%s), %d hops max, TCP SYN to port %d, %d probes/hop\n",
		cfg.Hostname, cfg.Target, cfg.MaxHops, cfg.Port, cfg.Probes)
}

// Hop prints one hop. locate is called once per distinct responding IP.
func Hop(w io.Writer, h tracer.Hop, locate func(net.IP) string) {
	ips := h.DistinctIPs()
	if len(ips) == 0 {
		fmt.Fprintf(w, "%2d  %s\n", h.TTL, strings.TrimSpace(strings.Repeat("* ", len(h.Probes))))
		return
	}

	rtts := h.RTTs()
	lo, avg, hi := Stats(rtts)
	fmt.Fprintf(w, "%2d  %-15s  %-45s  min/avg/max = %s/%s/%s ms  (%d/%d replies)%s\n",
		h.TTL, ips[0], locate(ips[0]), ms(lo), ms(avg), ms(hi), len(rtts), len(h.Probes),
		annotations(h))

	// Several routers answering one TTL = ECMP load balancing. Worth a
	// sentence in your traceroute comparison.
	for _, ip := range ips[1:] {
		fmt.Fprintf(w, "    %-15s  %-45s  (also answered this hop)\n", ip, locate(ip))
	}
}

// Footer prints the total hop count. Unanswered hops are counted, per spec.
func Footer(w io.Writer, hops []tracer.Hop) {
	n := len(hops)
	if n == 0 {
		return
	}
	last := hops[n-1]
	switch {
	case last.Reached:
		fmt.Fprintf(w, "\nDestination reached. Total hops: %d\n", n)
	case last.Blocked:
		fmt.Fprintf(w, "\nTrace stopped at hop %d: destination unreachable from %s%s\n",
			n, last.DistinctIPs()[0], annotations(last))
	default:
		fmt.Fprintf(w, "\nDestination not reached within %d hops.\n", n)
	}
}

// annotations renders traceroute-style flags for ICMP 3 codes, e.g. " !X".
// Each distinct flag is printed once.
func annotations(h tracer.Hop) string {
	var out string
	seen := map[string]bool{}
	for _, p := range h.Probes {
		if p.Kind != tracer.Unreachable {
			continue
		}
		f := unreachFlag(p.Code)
		if !seen[f] {
			seen[f] = true
			out += " " + f
		}
	}
	return out
}

// unreachFlag maps ICMP type 3 codes (RFC 792, RFC 1812) to traceroute's
// annotations.
func unreachFlag(code uint8) string {
	switch code {
	case 0:
		return "!N" // network unreachable
	case 1:
		return "!H" // host unreachable
	case 2:
		return "!P" // protocol unreachable
	case 3:
		return "!p" // port unreachable (UDP; unusual for TCP probes)
	case 4:
		return "!F" // fragmentation needed
	case 9, 10, 13:
		return "!X" // administratively prohibited
	default:
		return fmt.Sprintf("!<%d>", code)
	}
}

// Stats returns min/avg/max of d (all zero if d is empty).
func Stats(d []time.Duration) (lo, avg, hi time.Duration) {
	if len(d) == 0 {
		return
	}
	lo, hi = d[0], d[0]
	var sum time.Duration
	for _, x := range d {
		sum += x
		lo = min(lo, x)
		hi = max(hi, x)
	}
	return lo, sum / time.Duration(len(d)), hi
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000)
}