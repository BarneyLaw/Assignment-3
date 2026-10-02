package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// IPAPI queries http://ip-api.com (free tier: HTTP only, no key,
// 45 requests/minute). Results are cached per IP for the process lifetime,
// which matters because 3 probes per hop usually hit the same router.
type IPAPI struct {
	Client *http.Client

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	loc Location
	ok  bool
}

func NewIPAPI() *IPAPI {
	return &IPAPI{
		Client: &http.Client{Timeout: 3 * time.Second},
		cache:  make(map[string]cached),
	}
}

type ipapiResp struct {
	Status     string  `json:"status"`
	Message    string  `json:"message"`
	Country    string  `json:"country"`
	RegionName string  `json:"regionName"`
	City       string  `json:"city"`
	ISP        string  `json:"isp"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
}

func (api *IPAPI) Lookup(ctx context.Context, ip net.IP) (Location, bool, error) {
	key := ip.String()

	// Lock the cache and check if we already have a result for this IP.
	api.mu.Lock()
	if c, ok := api.cache[key]; ok {
		api.mu.Unlock()
		// c.ok=false means ip-api answered "fail" (e.g. reserved range): same
		// "no data" answer as the first lookup, not an error.
		return c.loc, c.ok, nil
	}
	api.mu.Unlock()

	// Make the HTTP request to ip-api.com.
	url := "http://ip-api.com/json/" + key +
	"?fields=status,message,country,regionName,city,isp,lat,lon"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Location{}, false, err
	}
	resp, err := api.Client.Do(req)
	if err != nil {
		return Location{}, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return Location{}, false, fmt.Errorf("rate limited by ip-api.com")
	}
	var r ipapiResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Location{}, false, fmt.Errorf("ip-api: decode: %w", err)
	}

	c := cached{ok: r.Status == "success"}
	if c.ok {
		c.loc = Location{
			City:    r.City,
			Region:  r.RegionName,
			Country: r.Country,
			Org:     r.ISP,
			Lat:     r.Lat,
			Lon:     r.Lon,
		}
	}
	api.mu.Lock()
	api.cache[key] = c
	api.mu.Unlock()
	return c.loc, c.ok, nil
}