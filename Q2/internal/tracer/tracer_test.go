package tracer

import (
	"net"
	"testing"
	"time"

	"geotrace/internal/packet"
)

// newTestTracer builds a Tracer without sockets, enough for the matchers.
func newTestTracer() *Tracer {
	return &Tracer{
		cfg: Config{
			Target: net.IPv4(93, 184, 216, 34).To4(),
			Port:   80,
			Probes: 3,
		},
		srcPort:  40000,
		inflight: make(map[uint32]*probe),
	}
}

func TestMatchTCPAcceptsEveryProbePort(t *testing.T) {
	tr := newTestTracer()
	for i := uint16(0); i < 3; i++ {
		seg := packet.TCPHeader{SrcPort: 80, DstPort: 40000 + i, Ack: 1001,
			Flags: packet.FlagSYN | packet.FlagACK}
		seq, kind, ok := tr.matchTCP(seg, tr.cfg.Target)
		if !ok || seq != 1000 || kind != TCPSynAck {
			t.Errorf("port %d: got (%d, %v, %v), want (1000, syn-ack, true)", 40000+i, seq, kind, ok)
		}
	}
	// One past the last probe port is not ours.
	seg := packet.TCPHeader{SrcPort: 80, DstPort: 40003, Ack: 1001, Flags: packet.FlagRST}
	if _, _, ok := tr.matchTCP(seg, tr.cfg.Target); ok {
		t.Error("matched a port outside the probe range")
	}
}

func TestMatchTCPKinds(t *testing.T) {
	tr := newTestTracer()
	cases := []struct {
		flags uint8
		want  ReplyKind
		ok    bool
	}{
		{packet.FlagSYN | packet.FlagACK, TCPSynAck, true},
		{packet.FlagRST | packet.FlagACK, TCPReset, true},
		{packet.FlagRST, TCPReset, true},
		{packet.FlagACK, TCPAck, true},
		{packet.FlagSYN, NoReply, false},
	}
	for _, c := range cases {
		seg := packet.TCPHeader{SrcPort: 80, DstPort: 40001, Ack: 6, Flags: c.flags}
		_, kind, ok := tr.matchTCP(seg, tr.cfg.Target)
		if kind != c.want || ok != c.ok {
			t.Errorf("flags %#x: got (%v, %v), want (%v, %v)", c.flags, kind, ok, c.want, c.ok)
		}
	}
	// Wrong source host.
	seg := packet.TCPHeader{SrcPort: 80, DstPort: 40000, Ack: 6, Flags: packet.FlagRST}
	if _, _, ok := tr.matchTCP(seg, net.IPv4(1, 1, 1, 1)); ok {
		t.Error("matched a reply from a host other than the target")
	}
}

func TestMatchICMPAcceptsEveryProbePort(t *testing.T) {
	tr := newTestTracer()
	msg := packet.ICMPError{
		Type:         packet.ICMPTimeExceeded,
		Inner:        packet.IPv4Header{Protocol: packet.ProtoTCP, Dst: tr.cfg.Target},
		InnerSrcPort: 40002,
		InnerDstPort: 80,
		InnerSeq:     777,
	}
	if seq, ok := tr.matchICMP(msg); !ok || seq != 777 {
		t.Errorf("got (%d, %v), want (777, true)", seq, ok)
	}
	msg.InnerSrcPort = 39999
	if _, ok := tr.matchICMP(msg); ok {
		t.Error("matched a quoted port outside the probe range")
	}
}

func TestReplyResultKeepsICMPCode(t *testing.T) {
	sent := time.Now()
	r := reply{kind: Unreachable, code: 13, from: net.IPv4(10, 0, 0, 1), at: sent.Add(5 * time.Millisecond)}
	got := r.result(&probe{sent: sent})
	if got.Code != 13 || got.Kind != Unreachable || got.RTT != 5*time.Millisecond {
		t.Errorf("got %+v", got)
	}
}

func TestClassify(t *testing.T) {
	hop := func(kinds ...ReplyKind) Hop {
		h := Hop{}
		for _, k := range kinds {
			h.Probes = append(h.Probes, ProbeResult{Kind: k})
		}
		return h
	}
	cases := []struct {
		name             string
		h                Hop
		reached, blocked bool
	}{
		{"one syn-ack is enough", hop(TCPSynAck, NoReply, NoReply), true, false},
		{"plain ack reaches", hop(NoReply, TCPAck, NoReply), true, false},
		{"rst reaches", hop(TCPReset, TCPReset, TCPReset), true, false},
		{"all unreachable", hop(Unreachable, Unreachable, Unreachable), false, true},
		{"two of three unreachable", hop(Unreachable, Unreachable, NoReply), false, true},
		{"one unreachable", hop(Unreachable, TimeExceeded, TimeExceeded), false, false},
		{"routers only", hop(TimeExceeded, TimeExceeded, NoReply), false, false},
		{"silent hop", hop(NoReply, NoReply, NoReply), false, false},
	}
	for _, c := range cases {
		r, b := classify(c.h)
		if r != c.reached || b != c.blocked {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", c.name, r, b, c.reached, c.blocked)
		}
	}
}
