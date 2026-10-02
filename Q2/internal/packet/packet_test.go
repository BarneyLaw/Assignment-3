package packet

import (
	"bytes"	
	"errors"
	"net"
	"testing"
)

var (
	srcIP = net.IPv4(192, 168, 1, 10).To4()
	dstIP = net.IPv4(1, 2, 3, 4).To4()
)

// RFC 1071 §3 worked example.
func TestChecksumRFC1071(t *testing.T) {
	in := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := Checksum(in); got != 0x220d {
		t.Fatalf("Checksum = %#04x, want 0x220d", got)
	}
}

func TestChecksumOddLength(t *testing.T) {
	// 0x01 is padded to the word 0x0100; ^0x0100 = 0xfeff.
	if got := Checksum([]byte{0x01}); got != 0xfeff {
		t.Fatalf("Checksum = %#04x, want 0xfeff", got)
	}
}

func TestPseudoHeader(t *testing.T) {
	want := []byte{192, 168, 1, 10, 1, 2, 3, 4, 0, 6, 0, 20}
	if got := pseudoHeader(srcIP, dstIP, ProtoTCP, 20); !bytes.Equal(got, want) {
		t.Fatalf("pseudoHeader = % x, want % x", got, want)
	}
}

func TestIPv4MarshalParseRoundTrip(t *testing.T) {
	h := IPv4Header{Version: 4, IHL: 5, TotalLen: 40, ID: 0xbeef, TTL: 7,
		Protocol: ProtoTCP, Src: srcIP, Dst: dstIP}
	b, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != IPv4HeaderLen || b[0] != 0x45 {
		t.Fatalf("bad header start: len=%d b[0]=%#x", len(b), b[0])
	}
	if Checksum(b) != 0 {
		t.Fatalf("IP header checksum does not verify")
	}
	got, rest, err := ParseIPv4(append(b, 0xaa, 0xbb))
	if err != nil {
		t.Fatal(err)
	}
	if got.TTL != 7 || got.ID != 0xbeef || got.Protocol != ProtoTCP ||
		!got.Src.Equal(srcIP) || !got.Dst.Equal(dstIP) || got.IHL != 5 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !bytes.Equal(rest, []byte{0xaa, 0xbb}) {
		t.Fatalf("payload = % x", rest)
	}
}

func TestParseIPv4Short(t *testing.T) {
	if _, _, err := ParseIPv4(make([]byte, 19)); !errors.Is(err, ErrShort) {
		t.Fatalf("err = %v, want ErrShort", err)
	}
	b := make([]byte, 20)
	b[0] = 0x46 // claims 24 bytes
	if _, _, err := ParseIPv4(b); !errors.Is(err, ErrShort) {
		t.Fatalf("IHL>len: err = %v, want ErrShort", err)
	}
}

func TestBuildSYNPacket(t *testing.T) {
	pkt, err := BuildSYNPacket(SYNParams{Src: srcIP, Dst: dstIP,
		SrcPort: 40000, DstPort: 80, Seq: 0x12345678, TTL: 3, ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 40 {
		t.Fatalf("len = %d, want 40", len(pkt))
	}
	ip, tcpBytes := pkt[:20], pkt[20:]
	if ip[8] != 3 || ip[9] != ProtoTCP || Checksum(ip) != 0 {
		t.Fatalf("bad IP header % x", ip)
	}
	if tcpBytes[12] != 0x50 || tcpBytes[13] != FlagSYN {
		t.Fatalf("bad TCP offset/flags % x", tcpBytes[12:14])
	}
	// The TCP checksum must verify over pseudo-header + segment.
	if Checksum(append(pseudoHeader(srcIP, dstIP, ProtoTCP, 20), tcpBytes...)) != 0 {
		t.Fatalf("TCP checksum does not verify")
	}
}

func TestParseTCPRstAck(t *testing.T) {
	b := []byte{
		0x00, 0x50, 0x9c, 0x40, // 80 -> 40000
		0x00, 0x00, 0x00, 0x00, // seq
		0x12, 0x34, 0x56, 0x79, // ack = our seq + 1
		0x50, 0x14, 0x00, 0x00, // offset 5, RST|ACK, window 0
		0x00, 0x00, 0x00, 0x00,
	}
	h, err := ParseTCP(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.SrcPort != 80 || h.DstPort != 40000 || h.Ack != 0x12345679 ||
		h.Flags != FlagRST|FlagACK || h.DataOffset != 5 {
		t.Fatalf("got %+v", h)
	}
}