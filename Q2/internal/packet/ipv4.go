package packet

import (
	"encoding/binary"
	"net"
)

// IPv4HeaderLen is the length of an IPv4 header without options.
const IPv4HeaderLen = 20

// ProtoTCP and ProtoICMP are the IPv4 protocol numbers we care about.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
)

// IPv4Header is a decoded IPv4 header. Options are skipped, not stored.
//
// Wire layout (RFC 791), byte offsets:
//
//	0: version(4 bits) | IHL(4 bits, in 32-bit words)
//	1: TOS
//	2: total length        (uint16)
//	4: identification      (uint16)
//	6: flags(3) | frag off (uint16 together)
//	8: TTL
//	9: protocol
//	10: header checksum    (uint16)
//	12: source address     (4 bytes)
//	16: destination address(4 bytes)
type IPv4Header struct {
	Version  uint8
	IHL      uint8 // header length in 32-bit words; 5 means 20 bytes
	TOS      uint8
	TotalLen uint16
	ID       uint16
	FlagsOff uint16 // flags + fragment offset, kept packed
	TTL      uint8
	Protocol uint8
	Checksum uint16
	Src      net.IP
	Dst      net.IP
}

// Marshal encodes h as a 20-byte header (no options) and fills in the
// header checksum (computed over the header with the checksum field zeroed).
//
// Note on Linux + IP_HDRINCL (raw(7)): the kernel always rewrites the IP
// checksum and total length, so a wrong value here will NOT show up in
// Wireshark. Compute it properly anyway; the tests check it.
func (h *IPv4Header) Marshal() ([]byte, error) {
	// TODO(you): implement.
	buf := make([]byte, IPv4HeaderLen) // create a buffer of 20 bytes for the header

	buf[0] = (h.Version << 4) | (h.IHL & 0x0F) // version and IHL packed into first byte
	buf[1] = h.TOS
	binary.BigEndian.PutUint16(buf[2:4], h.TotalLen)
	binary.BigEndian.PutUint16(buf[4:6], h.ID)
	binary.BigEndian.PutUint16(buf[6:8], h.FlagsOff)
	buf[8] = h.TTL
	buf[9] = h.Protocol
	// Checksum is initially set to 0 for calculation
	binary.BigEndian.PutUint16(buf[10:12], 0)
	copy(buf[12:16], h.Src.To4())
	copy(buf[16:20], h.Dst.To4())

	// Calculate checksum over the header with checksum field zeroed
	h.Checksum = Checksum(buf)
	binary.BigEndian.PutUint16(buf[10:12], h.Checksum)

	return buf, nil
}

// ParseIPv4 decodes the IPv4 header at the start of b and returns it along
// with the bytes that follow the header.
//
// It MUST honour IHL: a header with options is longer than 20 bytes, and
// the quoted header inside an ICMP error can carry options (20 to 60 bytes).
// Return ErrShort if b is shorter than 20 bytes or shorter than IHL*4.
func ParseIPv4(b []byte) (IPv4Header, []byte, error) {
	// TODO(you): implement.
	header := IPv4Header{}
	if len(b) < IPv4HeaderLen || len(b) < int(b[0]&0x0F)*4 {
		return header, nil, ErrShort
	}

	header.Version = b[0] >> 4
	header.IHL = b[0] & 0x0F
	header.TOS = b[1]
	header.TotalLen = binary.BigEndian.Uint16(b[2:4])
	header.ID = binary.BigEndian.Uint16(b[4:6])
	header.FlagsOff = binary.BigEndian.Uint16(b[6:8])
	header.TTL = b[8]
	header.Protocol = b[9]
	header.Checksum = binary.BigEndian.Uint16(b[10:12])
	header.Src = net.IPv4(b[12], b[13], b[14], b[15]).To4()
	header.Dst = net.IPv4(b[16], b[17], b[18], b[19]).To4()

	return header, b[int(header.IHL)*4:], nil
	
}