// Package tracer runs the TTL loop: send TCP SYN probes, collect ICMP and
// TCP replies, match them to probes, time them.
//
// Concurrency model:
//
//	main goroutine ── probeHop(ttl) ──▶ send N probes, then wait ≤ Timeout
//	                                       ▲
//	icmp reader goroutine ─┐                │ reply via per-probe chan
//	tcp  reader goroutine ─┴─▶ match ──▶ deliver(seq)
//
// Probe identity: probe i of every hop uses source port srcPort+i, so each
// probe "column" has a FIXED 5-tuple (src, dst, srcPort+i, dstPort, TCP) for
// the whole run, and each probe gets a unique random TCP sequence number.
// The seq comes back in two places:
//   - ICMP errors quote our IP header + first 8 TCP bytes (ports + seq)
//   - the destination's RST / SYN-ACK acknowledges seq+1
//
// Keeping each column's 5-tuple fixed means ECMP routers hash it onto the
// same path at every TTL (the "Paris traceroute" idea). Classic UDP
// traceroute changes the dst port per probe, which is why it can show
// different routers at one hop. Good material for the comparison section.
//
// Why not one port for all probes: the probes of a hop go out back to back.
// At an open destination port, SYN #1 puts the server into SYN-RECEIVED for
// that 5-tuple, and SYN #2/#3 arrive before our kernel's RST has cleared it,
// so the server re-sends SYN-ACK #1 (or a challenge ACK) instead of answering
// them. Separate ports make each probe a separate connection attempt.
package tracer

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"geotrace/internal/packet"
)

type probe struct {
	ttl int
	seq uint32
	sent time.Time
	ch chan reply // buffered[1]: first matching reply wins
}

type reply struct {
	kind ReplyKind
	from net.IP
	code uint8
	at   time.Time
}

// Tracer is single-use: New, Run, Close.
type Tracer struct {
	cfg     Config
	socks   *sockets
	srcPort uint16 // base port; probe i of each hop uses srcPort+i

	mu       sync.Mutex
	inflight map[uint32]*probe // keyed by seq
}

func New(cfg Config) (*Tracer, error) {
	sock, err := openSockets()
	if err != nil {
		return nil, err
	}
	return &Tracer{
		cfg:      cfg,
		socks:    sock,
		// leave room for srcPort+Probes-1 without wrapping past 65535
		srcPort:  uint16(rand.IntN(65536-1024-cfg.Probes) + 1024),
		inflight: make(map[uint32]*probe),
	}, nil
}

// Close closes all three raw sockets.
func (t *Tracer) Close() error {
	t.socks.close()
	return nil
}

// ownsPort reports whether port is one of our probe source ports.
func (t *Tracer) ownsPort(port uint16) bool {
	return port >= t.srcPort && int(port) < int(t.srcPort)+t.cfg.Probes
}

// Run traces hop by hop, calling onHop as each completes so output streams
// like real traceroute. It returns every hop once the destination answers
// or MaxHops is exhausted.
func (t *Tracer) Run(ctx context.Context, onHop func(Hop)) ([]Hop, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go t.readLoop(ctx, t.socks.icmp, t.handleICMP)
	go t.readLoop(ctx, t.socks.tcp, t.handleTCP)

	var hops []Hop
	// iterate TTLs from 1 to MaxHops, sending probes and collecting replies
	for ttl := 1; ttl <= t.cfg.MaxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return hops, err
		}
		h, err := t.probeHop(ctx, ttl)
		if err != nil {
			return hops, err
		}
		
		hops = append(hops, h)
		if onHop != nil {
			onHop(h)
		}

		if h.Done() {
			break
		}
	}

	return hops, nil
}

// probeHop sends all probes for one TTL back to back, then waits for them
// together. Worst case is MaxHops*Timeout instead of MaxHops*Probes*Timeout.
func (t *Tracer) probeHop(ctx context.Context, ttl int) (Hop, error) {
	probes := make([]*probe, t.cfg.Probes)

	// Unregister every probe at the end of this hop, whether it got a reply,
	// timed out, or we bailed out early on a send error (nil = never registered).
	defer func() {
		for _, p := range probes {
			if p != nil {
				t.unregister(p.seq)
			}
		}
	}()

	for i := range probes {
		p := t.register(ttl)
		probes[i] = p
		pkt, err := packet.BuildSYNPacket(packet.SYNParams{
			Src: t.cfg.SrcIP, 
			Dst: t.cfg.Target,
			SrcPort: t.srcPort + uint16(i), // one fixed flow per probe column
			DstPort: t.cfg.Port,
			Seq: p.seq, 
			TTL: uint8(ttl), 
			ID: uint16(p.seq),
		})
		if err != nil {
			return Hop{}, err
		}
		p.sent = time.Now()
		if err := t.socks.send(pkt, t.cfg.Target); err != nil {
			return Hop{}, err
		}
	}

	deadline := time.NewTimer(t.cfg.Timeout)
	defer deadline.Stop()

	hop := Hop{TTL: ttl, Probes: make([]ProbeResult, len(probes))}
	timedOut:= false
	for i, p := range probes {
		if timedOut {
			break
		}
		select {
		case r := <-p.ch:
			hop.Probes[i] = r.result(p)
		case <-deadline.C:
			timedOut = true
		case <-ctx.Done():
			return hop, ctx.Err()
		}
	}

	// A late reply for an earlier probe could still be sitting in its chan
	// after the timer fired; drain without blocking.
	for i, p := range probes {
		if hop.Probes[i].Kind != NoReply {
			continue
		}
		select {
		case r := <-p.ch:
			hop.Probes[i] = r.result(p)
		default:
		}
	}

	hop.Reached, hop.Blocked = classify(hop)
	return hop, nil
}

// result turns a matched reply into the ProbeResult for probe p.
func (r reply) result(p *probe) ProbeResult {
	return ProbeResult{
		Kind: r.kind,
		Code: r.code,
		From: r.from,
		RTT:  r.at.Sub(p.sent),
	}
}

// classify returns (reached, blocked) for a hop. Reached means the destination
// answered at this TTL. Blocked means all but at most one probe got ICMP
// unreachable (e.g. a firewall); this is the same rule classic traceroute
// uses (unreachable >= nprobes-1), so one lost reply doesn't keep us going.
func classify(h Hop) (reached, blocked bool) {
	unreach := 0
	for _, p := range h.Probes {
		switch p.Kind {
		case TCPReset, TCPSynAck, TCPAck:
			return true, false
		case Unreachable:
			unreach++
		}
	}
	return false, unreach > 0 && unreach >= len(h.Probes)-1
}

// register allocates a probe for the given TTL and returns it. The caller
func (t *Tracer) register(ttl int) *probe {
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		seq := rand.Uint32()
		if _, dup := t.inflight[seq]; !dup {
			p:= &probe{
				ttl:  ttl,
				seq:  seq,
				ch:   make(chan reply, 1),
			}
			t.inflight[seq] = p
			return p
		}
	}
}

// unregister removes a probe from the inflight map. It is called when a probe
// has either received a reply or timed out. This prevents late replies from
// being delivered to a probe that is no longer waiting for them.
func (t *Tracer) unregister(seq uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.inflight, seq)
}


// deliver routes a matched reply to its probe. Duplicates (routers do send
// them) are dropped because the chan only holds one.
func (t *Tracer) deliver(seq uint32, r reply) {
	t.mu.Lock()
	p, ok := t.inflight[seq]
	t.mu.Unlock()
	if !ok {
		return // late reply for a hop we already gave up on
	}
	select {
	case p.ch <- r:
	default:
	}
}

// readLoop reads one raw socket until ctx is cancelled. The short read
// deadline is only there so we notice cancellation.
func (t *Tracer) readLoop(ctx context.Context, c net.PacketConn,
	handle func(b []byte, from net.IP, at time.Time)) {
	buf := make([]byte, 1500)
	for {
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := c.ReadFrom(buf)
		at := time.Now()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		ipAddr, ok := addr.(*net.IPAddr)
		if !ok {
			continue
		}
		// handle must not keep buf; the parsers copy what they need.
		handle(buf[:n], ipAddr.IP, at)
	}
}

func (t *Tracer) handleICMP(b []byte, from net.IP, at time.Time) {
	msg, err := packet.ParseICMPError(b)
	if err != nil {
		return // not ours / not an error message / malformed
	}
	seq, ok := t.matchICMP(msg)
	if !ok {
		return
	}

	r := reply{kind: TimeExceeded, from: from, at: at}
	if msg.Type == packet.ICMPDestUnreachable {
		r.kind , r.code = Unreachable, msg.Code
	}
	t.deliver(seq, r)
}

func (t *Tracer) handleTCP(b []byte, from net.IP, at time.Time) {
	seg, err := packet.ParseTCP(b)
	if err != nil {
		return
	}
	seq, kind, ok := t.matchTCP(seg, from)
	if !ok {
		return
	}
	t.deliver(seq, reply{kind: kind, from: from, at: at})
}

// matchICMP is the "ICMP Response Validation" requirement: prove that this
// ICMP error was caused by one of OUR probes, and return its seq.
//
// return (msg.InnerSeq, true) only if ALL of these hold:
//   - quoted protocol is TCP
//   - quoted destination IP is t.cfg.Target
//   - quoted src port is one of our probe ports and quoted dst port is t.cfg.Port
//
// Do NOT check the quoted source IP against t.cfg.SrcIP: behind a NAT the
// router quotes the post-NAT address. (Most NATs rewrite the quote back,
// but don't depend on it.) The seq lookup in deliver() does the rest.
func (t *Tracer) matchICMP(msg packet.ICMPError) (seq uint32, ok bool) {

	if msg.Inner.Protocol != packet.ProtoTCP {
		return 0, false
	}
	if !msg.Inner.Dst.Equal(t.cfg.Target) {
		return 0, false
	}
	if !t.ownsPort(msg.InnerSrcPort) || msg.InnerDstPort != t.cfg.Port {
		return 0, false
	}

	return msg.InnerSeq, true
}

// matchTCP recognises the destination's answer to a probe.
//
// return (seg.Ack-1, TCPReset|TCPSynAck|TCPAck, true) only if:
//   - from is t.cfg.Target
//   - seg.SrcPort == t.cfg.Port and seg.DstPort is one of our probe ports
//   - flags contain both SYN and ACK, or RST, or ACK alone
//     (check SYN+ACK first; RST+ACK is the usual closed-port reply)
//
// Why Ack-1: a SYN consumes one sequence number, so a SYN-ACK, the RST,ACK
// to a closed port, and an open port's plain ACK all acknowledge our seq+1
// (RFC 793 §3.4). A plain ACK whose Ack is NOT seq+1 (e.g. an RFC 5961
// challenge ACK for some older connection) maps to no in-flight probe and
// is dropped by deliver().
//
// Side effect to know about: after a SYN-ACK, your kernel has no socket for
// that connection, so it sends its own RST. Harmless; you will see it in
// Wireshark.
func (t *Tracer) matchTCP(seg packet.TCPHeader, from net.IP) (seq uint32, kind ReplyKind, ok bool) {
	if !from.Equal(t.cfg.Target) {
		return 0, NoReply, false
	}

	if seg.SrcPort != t.cfg.Port || !t.ownsPort(seg.DstPort) {
		return 0, NoReply, false
	}

	// Check for SYN+ACK first (open-port reply)
	if (seg.Flags & (packet.FlagSYN| packet.FlagACK)) == (packet.FlagSYN| packet.FlagACK) {
		return seg.Ack - 1, TCPSynAck, true
	}

	// Check for RST (closed-port reply, covers both raw RST and RST+ACK)
	if (seg.Flags & packet.FlagRST) != 0 {
		return seg.Ack - 1, TCPReset, true
	}

	// Plain ACK (open-port reply from some stacks; the spec lists it too)
	if seg.Flags&packet.FlagACK != 0 {
		return seg.Ack - 1, TCPAck, true
	}

	return 0, NoReply, false
}