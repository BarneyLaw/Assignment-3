// Package packet builds and parses the raw bytes geotrace puts on and takes
// off the wire: the IPv4 header, the TCP header (with pseudo-header checksum)
// and ICMP error messages with their quoted IP + TCP headers.
//
// Everything here is pure byte manipulation with encoding/binary. No sockets,
// so the whole package is unit-testable without root (see *_test.go).
//
// All multi-byte fields are network byte order (big-endian). Use
// binary.BigEndian everywhere; never byte-swap by hand.
package packet

import "errors"

// ErrShort is returned when a buffer is too small for the header being parsed.
var ErrShort = errors.New("packet: buffer too short")