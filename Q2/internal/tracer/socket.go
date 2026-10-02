package tracer

import (
	"fmt"
	"net"
	"syscall"
)	

// sockets holds the three raw sockets the assignment asks for:
//
//	send: SOCK_RAW/IPPROTO_TCP with IP_HDRINCL, we write IP+TCP ourselves
//	icmp: SOCK_RAW/IPPROTO_ICMP, receives every ICMP packet to this host
//	tcp:  SOCK_RAW/IPPROTO_TCP, receives a COPY of every TCP segment to
//	      this host (the kernel still processes the original)
//
// The receivers use net.ListenPacket("ip4:..."), which is still a raw
// socket underneath but gives us read deadlines. Gotcha: on Linux, Go's
// IPConn strips the outer IPv4 header on read, so buffers start at the
// ICMP/TCP header and the sender's address comes from ReadFrom.
type sockets struct {
	sendFD int
	icmp   net.PacketConn
	tcp    net.PacketConn
}

// openSockets opens the three raw sockets. The caller must call close() on the result.
func openSockets() (*sockets, error) {
	// Open a raw socket for sending TCP packets. We need to set IP_HDRINCL so the kernel doesn't add its own IP header.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("open send socket: %w", err)
	}
	// Set the socket option IP_HDRINCL to 1, which tells the kernel that we will provide our own IP header in the packets we send. 
	// This is necessary for raw sockets when we want to construct the entire packet ourselves.
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
	}

	// Open a raw socket for receiving ICMP packets. This socket will receive all ICMP packets sent to this host.
	icmp, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("raw icmp socket: %w", err)
	}
	tcp, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		syscall.Close(fd)
		icmp.Close()
		return nil, fmt.Errorf("raw tcp recv socket: %w", err)
	}
	return &sockets{sendFD: fd, icmp: icmp, tcp: tcp}, nil
}

func (s *sockets) send(pkt []byte, dst net.IP) error {
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst.To4())
	return syscall.Sendto(s.sendFD, pkt, 0, &sa)
}

func (s *sockets) close() {
	s.icmp.Close()
	s.tcp.Close()
	syscall.Close(s.sendFD)
}

// LocalIPFor returns the source address the kernel would use to reach dst.
// We need it for the IP header and the TCP pseudo-header. "Dialing" UDP
// sends no packets; it just runs a route lookup.
func LocalIPFor(dst net.IP) (net.IP, error) {
	c, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.To4(), nil
}