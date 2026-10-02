package packet

import (
	"encoding/binary"
	"errors"
	"net"
)

// TCPHeaderLen is the length of a TCP header without options.
const TCPHeaderLen = 20

// TCP flag bits (byte 13 of the header).
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

// TCPHeader is a decoded TCP header. Options are skipped.
//
// Wire layout (RFC 793), byte offsets:
//
//	0: source port   (uint16)
//	2: dest port     (uint16)
//	4: sequence no.  (uint32)
//	8: ack no.       (uint32)
//	12: data offset(4 bits, in 32-bit words) | reserved(4 bits)
//	13: flags
//	14: window       (uint16)
//	16: checksum     (uint16)
//	18: urgent ptr   (uint16)
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8 // in 32-bit words; 5 means 20 bytes
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

// Marshal encodes h as a 20-byte header and fills in the checksum, computed
// over pseudoHeader(src, dst, ProtoTCP, 20) followed by the header with its
// checksum field zeroed.
func (h *TCPHeader) Marshal(src, dst net.IP) ([]byte, error) {
	buf := make([]byte, TCPHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], h.Seq)
	binary.BigEndian.PutUint32(buf[8:12], h.Ack)
	buf[12] = (h.DataOffset << 4) | 0 // reserved bits are zero
	buf[13] = h.Flags
	binary.BigEndian.PutUint16(buf[14:16], h.Window)
	// checksum is computed below
	binary.BigEndian.PutUint16(buf[18:20], h.Urgent)

	// Compute the checksum over the pseudo-header and the TCP header with checksum field zeroed.
	pseudo := pseudoHeader(src, dst, ProtoTCP, uint16(len(buf)))
	if pseudo == nil {
		return nil, errors.New("invalid IP addresses for pseudo-header")
	}
	checksumData := append(pseudo, buf...)
	binary.BigEndian.PutUint16(buf[16:18], Checksum(checksumData))

	return buf, nil
}

// ParseTCP decodes the TCP header at the start of b.
// Return ErrShort if b is shorter than 20 bytes.
func ParseTCP(b []byte) (TCPHeader, error) {
	if len(b) < TCPHeaderLen {
		return TCPHeader{}, ErrShort
	}
	return TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(b[0:2]),
		DstPort:    binary.BigEndian.Uint16(b[2:4]),
		Seq:        binary.BigEndian.Uint32(b[4:8]),
		Ack:        binary.BigEndian.Uint32(b[8:12]),
		DataOffset: b[12] >> 4,
		Flags:      b[13],
		Window:     binary.BigEndian.Uint16(b[14:16]),
		Checksum:   binary.BigEndian.Uint16(b[16:18]),
		Urgent:     binary.BigEndian.Uint16(b[18:20]),
	}, nil
}


// SYNParams describes one probe.
type SYNParams struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	Seq              uint32
	TTL              uint8
	ID               uint16 // IP identification; any value, handy in Wireshark
}

// BuildSYNPacket returns a complete IPv4 + TCP SYN packet (40 bytes) ready
// to hand to a raw socket with IP_HDRINCL set. This is glue; the real work
// is in IPv4Header.Marshal and TCPHeader.Marshal.
func BuildSYNPacket(p SYNParams) ([]byte, error) {
	tcp := TCPHeader{
		SrcPort:    p.SrcPort,
		DstPort:    p.DstPort,
		Seq:        p.Seq,
		DataOffset: 5,
		Flags:      FlagSYN,
		Window:     64240,
	}
	tcpBytes, err := tcp.Marshal(p.Src, p.Dst)
	if err != nil {
		return nil, err
	}

	ip := IPv4Header{
		Version:  4,
		IHL:      5,
		TotalLen: uint16(IPv4HeaderLen + len(tcpBytes)),
		ID:       p.ID,
		TTL:      p.TTL,
		Protocol: ProtoTCP,
		Src:      p.Src,
		Dst:      p.Dst,
	}
	ipBytes, err := ip.Marshal()
	if err != nil {
		return nil, err
	}
	return append(ipBytes, tcpBytes...), nil
}

