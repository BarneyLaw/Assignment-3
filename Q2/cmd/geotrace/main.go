package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"geotrace/internal/geo"
	"geotrace/internal/report"
	"geotrace/internal/tracer"
)

func main() {
	port := flag.Int("p", 80, "TCP port to probe")
	timeout := flag.Duration("t", 2*time.Second, "timeout per hop")
	probes := flag.Int("n", 3, "probes per hop")
	maxHops := flag.Int("m", 30, "maximum hops to trace")
	geoBackend := flag.String("geo", "ipapi", "geolocation backend (ipapi or none)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] hostname\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(flag.Arg(0), uint16(*port), *maxHops, *probes, *timeout, *geoBackend); err != nil {
		fmt.Fprintln(os.Stderr, "geotrace:", err)
		os.Exit(1)
	}
}

func run(host string, port uint16, maxHops, probes int, timeout time.Duration, geoBackend string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	target, err := resolveIPv4(host)
	if err != nil {
		return err
	}

	src, err := tracer.LocalIPFor(target)
	if err != nil {
		return fmt.Errorf("finding local IP for %s: %w", target, err)
	}

	var loc geo.Locator = geo.Nop{}
	if geoBackend == "ipapi" {
		loc = geo.NewIPAPI()
	}

	cfg := tracer.Config{
		Hostname: host,
		Target:   target,
		SrcIP:    src,
		Port:     port,
		MaxHops:  maxHops,
		Probes:   probes,
		Timeout:  timeout,
	}
	
	t, err := tracer.New(cfg)
	if err != nil {
		return err
	}

	defer t.Close()

	locate := func(ip net.IP) string {
		return geo.Describe(ctx, loc, ip)
	}
	
	report.Header(os.Stdout, cfg)
	hops, err := t.Run(ctx, func(h tracer.Hop) { report.Hop(os.Stdout, h, locate) })
	report.Footer(os.Stdout, hops)
	return err
}


func resolveIPv4(host string) (net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("%s has no IPv4 address", host)

}
	
