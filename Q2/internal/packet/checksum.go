package packet

import (
	"encoding/binary"
	"net"
)

// Checksum computes the RFC 1071 Internet checksum over b.
//
// Algorithm:
//  1. Sum b as a sequence of big-endian 16-bit words into a uint32.
//     If len(b) is odd, treat the last byte as the HIGH byte of a final word
//     (i.e. pad with a zero byte on the right).
//  2. Fold carries: while sum>>16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
//  3. Return the one's complement: ^uint16(sum)
//
// Store the result with binary.BigEndian.PutUint16. Useful property for
// testing: running Checksum over data that already contains a correct
// checksum field returns 0.
func Checksum(b []byte) uint16 {
	var sum uint32
	length := len(b)

	// Combine adjacent bytes into 16-bit words and sum them. (literally combine 8 bits into 16 bits)
	for i := 0; i < length - 1; i += 2 {
		word := binary.BigEndian.Uint16(b[i : i+2])
		sum += uint32(word)
	}

	if length % 2 == 1 {
		// Pad with a zero byte on the right
		// This is done by shifting the last byte to the left by 8 bits 
		// (making it the high byte of a 16-bit word) 
		// and adding it to the sum. The sum does not originally include the last byte, so we need to add it in this way.
		sum += uint32(b[length-1]) << 8 
	}

	for sum >> 16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum) // 1's complement
}


// pseudoHeader returns the 12-byte TCP/UDP pseudo-header (RFC 793 §3.1):
//
//	0      4      8      9       10       12
//	| src  | dst  | zero | proto | length |
//
// length is the TCP header + payload length (20 for a bare SYN), not the
// IP total length. The pseudo-header is only fed into the checksum; it is
// never transmitted.
func pseudoHeader(src, dst net.IP, proto uint8, length uint16) []byte {
	var buf [12]byte
	buf[0] = src[0]
	buf[1] = src[1]
	buf[2] = src[2]
	buf[3] = src[3]
	buf[4] = dst[0]
	buf[5] = dst[1]
	buf[6] = dst[2]
	buf[7] = dst[3]
	buf[8] = 0
	buf[9] = proto
	binary.BigEndian.PutUint16(buf[10:12], length)
	return buf[:]
}
