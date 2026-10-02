package tracer

import (
	"net"
	"time"
)

// Config is everything a trace needs. main fills it from flags.
type Config struct {
	Hostname string        // for display only
	Target   net.IP        // resolved IPv4 destination
	SrcIP    net.IP        // our address on the outgoing interface
	Port     uint16        // destination port (80/443 rarely firewalled)
	MaxHops  int           // spec: 30
	Probes   int           // spec: 3
	Timeout  time.Duration // how long to wait for a hop's replies
}

// ReplyKind says what answered a probe.
type ReplyKind int

const (
	NoReply      ReplyKind = iota
	TimeExceeded           // ICMP 11 from a router on the path
	Unreachable            // ICMP 3 (e.g. admin-prohibited firewall)
	TCPReset               // destination port closed
	TCPSynAck              // destination port open
	TCPAck                 // destination port open (plain ACK instead of SYN-ACK)
)

func (k ReplyKind) String() string {
	return [...]string{"none", "time-exceeded", "unreachable", "rst", "syn-ack", "ack"}[k]
}

// ProbeResult is the outcome of one probe.
type ProbeResult struct {
	Kind ReplyKind
	Code uint8        // ICMP code (0..15) for TimeExceeded/Unreachable, else 0
	From net.IP        // nil if NoReply
	RTT  time.Duration // zero if NoReply
}

// Hop is the outcome of all probes sent with one TTL.
type Hop struct {
	TTL     int
	Probes  []ProbeResult
	Reached bool // destination answered at this TTL
	Blocked bool // all but at most one probe got ICMP unreachable (e.g. firewall)
}

// Done returns true if the trace is finished at this hop (destination answered or all probes blocked).
func (h Hop) Done() bool { return h.Reached || h.Blocked }

// DistinctIPs returns the responding addresses in a first-seen order
func (h Hop) DistinctIPs() []net.IP {
	var out []net.IP
	for _, p := range h.Probes {
		if p.From == nil {
			continue
		}
		seen := false
		for _, ip := range out {
			if p.From.Equal(ip) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, p.From)
		}
	}
	return out
}

// RTTs returns the RTTs of answered probes only (spec: stats over valid
// responses).
func (h Hop) RTTs() []time.Duration {
	var out []time.Duration
	for _, p := range h.Probes {
		if p.Kind != NoReply {
			out = append(out, p.RTT)
		}
	}
	return out
}