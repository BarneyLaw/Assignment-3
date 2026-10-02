# geotrace (CS3103 Assignment 3, Part B)

TCP SYN traceroute over raw sockets, with per-hop geolocation. Linux only.

## Build and run

    make                         # go build -o bin/geotrace ./cmd/geotrace  (Go 1.22+)
    sudo ./bin/geotrace www.harvard.edu
    sudo ./bin/geotrace -p 443 -w 1s -geo none example.com
    make test                    # packet-layer unit tests, no root needed

Flags: `-p` dst port (80), `-m` max hops (30), `-q` probes/hop (3),
`-w` wait per hop (2s), `-geo` ipapi | none.

## Layout

    cmd/geotrace/       CLI, DNS resolution, wiring
    internal/packet/    IPv4/TCP build + parse, ICMP error parse, RFC 1071 checksum
                        (pure functions, unit-tested)
    internal/tracer/    raw sockets, TTL loop, reply matching, timing
    internal/geo/       Locator interface, ip-api.com backend with cache
    internal/report/    output formatting, min/avg/max

## Design notes

- Probe ID lives in the TCP sequence number; the 5-tuple is constant per run,
  so ECMP routers keep all probes on one path (Paris-traceroute style).
- ICMP errors are validated by parsing the quoted IP header (honouring IHL)
  and the quoted 8 TCP bytes: protocol, dst IP, both ports, seq.
- The destination's RST or SYN-ACK is matched via ack - 1 == seq sent.
- Probes for one TTL are sent back to back and awaited together.

## Comparison

    sudo traceroute -T -p 80 www.harvard.edu   # same probe type: fair comparison
    traceroute www.harvard.edu                 # default UDP: may differ (ECMP, filtering)
