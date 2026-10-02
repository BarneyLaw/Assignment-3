package packet

import (
	"encoding/binary"
	"errors"
)

// ICMP types we handle (RFC 792). Everything else is ignored.
const (
	ICMPDestUnreachable = 3
	ICMPTimeExceeded    = 11
)

// ErrNotICMPError means the message is a valid ICMP message but not a
// type 3 / type 11 error (e.g. an echo reply from someone's ping). Callers
// should silently drop these.
var ErrNotICMPError = errors.New("packet: not an ICMP error message")

// ICMPError is a decoded ICMP Destination Unreachable or Time Exceeded
// message, including the identifying fields of the packet that caused it.
//
// Wire layout of b (the outer IP header has already been stripped):
//
//	0: type
//	1: code
//	2: checksum            (uint16)
//	4: unused / next-hop MTU (4 bytes)
//	8: quoted IP header    (IHL*4 bytes, 20..60)
//	8+IHL*4: first 8 bytes of the quoted transport header
//	         for TCP that is: src port(2) dst port(2) seq(4)
type ICMPError struct {
	Type uint8
	Code uint8

	Inner        IPv4Header // quoted IP header of OUR probe
	InnerSrcPort uint16     // from the quoted 8 TCP bytes
	InnerDstPort uint16
	InnerSeq     uint32
}

// ParseICMPError decodes b, which starts at the ICMP header.
//
//   - Return ErrShort if b is too short at any stage.
//   - Return ErrNotICMPError for any type other than 3 or 11.
//   - Use ParseIPv4 for the quoted header so IHL > 5 is handled.
//   - You only get 8 bytes of TCP, so do NOT call ParseTCP (it needs 20).
//   - Don't reject on the quoted TTL; routers report it as 0 or 1.
func ParseICMPError(b []byte) (ICMPError, error) {
	if len(b) < 8 {
		return ICMPError{}, ErrShort
	}

	icmpType := b[0]
	icmpCode := b[1]

	if icmpType != ICMPDestUnreachable && icmpType != ICMPTimeExceeded {
		return ICMPError{}, ErrNotICMPError
	}

	payload := b[8:] // skip type, code, checksum, unused/next-hop MTU

	innerIP, rest, err := ParseIPv4(payload)

	if err != nil {
		return ICMPError{}, err
	}

	if len(rest) < 8 {
		return ICMPError{}, ErrShort
	}
	
	innerSrcPort := binary.BigEndian.Uint16(rest[0:2])
	innerDstPort := binary.BigEndian.Uint16(rest[2:4])
	innerSeq := binary.BigEndian.Uint32(rest[4:8])
	
	return ICMPError{
		Type:         icmpType,
		Code:         icmpCode,
		Inner:        innerIP,
		InnerSrcPort: innerSrcPort,
		InnerDstPort: innerDstPort,
		InnerSeq:     innerSeq,
	}, nil
}