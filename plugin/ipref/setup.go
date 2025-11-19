package ipref

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/miekg/dns"
	"net"
	"strings"
)

func init() {
	caddy.RegisterPlugin("ipref", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	ipr, err := iprefParse(c)
	if err != nil {
		return plugin.Error("ipref", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ipr.Next = next
		return ipr
	})

	c.OnStartup(func() error {
		once.Do(func() {
			m := dnsserver.GetConfig(c).Handler("prometheus")
			if m == nil {
				return
			}
			if x, ok := m.(*metrics.Metrics); ok {
				x.MustRegister(RequestDuration)
				x.MustRegister(RcodeCount)
			}
		})
		return nil
	})
	c.OnShutdown(ipr.Stop)

	return nil
}

func iprefParse(c *caddy.Controller) (*Ipref, error) {
	ipr := &Ipref{
		m: &MapperClient{},
		ea_ipver: 0,
		gw_ipver: 0,
		mapper_socket: "",
	}

	mapper_socket_dir := "/var/run/ipref-gw"

	i := 0
	for c.Next() {
		// Return an error if ipref block specified more than once
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		ipr.from = c.RemainingArgs()
		if len(ipr.from) == 0 {
			ipr.from = make([]string, len(c.ServerBlockKeys))
			copy(ipr.from, c.ServerBlockKeys)
		}
		for i, str := range ipr.from {
			ipr.from[i] = plugin.Host(str).NormalizeExact()[0]
		}

		for c.NextBlock() {
			name := c.Val()
			switch name {
			case "except":
				except := c.RemainingArgs()
				if len(except) == 0 {
					return nil, c.ArgErr()
				}
				for i := 0; i < len(except); i++ {
					except[i] = plugin.Host(except[i]).NormalizeExact()[0]
				}
				ipr.except = except

			case "upstream":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ipr.upstream = strings.TrimSpace(args[0])
				if !addrHasPort(ipr.upstream) {
					ipr.upstream += ":53"
				}

			case "ea-ipver", "gw-ipver":
				ipv4 := false
				ipv6 := false
				for _, arg := range c.RemainingArgs() {
					switch arg {
					case "4": ipv4 = true
					case "6": ipv6 = true
					default: return nil, c.ArgErr()
					}
				}
				var ipver int
				switch {
				case ipv4 && ipv6:  ipver = 0
				case ipv4 && !ipv6: ipver = 4
				case !ipv4 && ipv6: ipver = 6
				default: return nil, c.ArgErr()
				}
				if name == "ea-ipver" {
					ipr.ea_ipver = ipver
				} else {
					ipr.gw_ipver = ipver
				}

			case "mapper":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ipr.mapper_socket = args[0]

			case "mapper-socket-dir":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				mapper_socket_dir = args[0]

			default:
				return nil, c.ArgErr()
			}
		}
	}

	if ipr.upstream == "" {
		return nil, fmt.Errorf("missing upstream")
	}

	ipr.gw_dns_types = make([]uint16, 0, 2)
	if ipr.gw_ipver == 0 || ipr.gw_ipver == 6 {
		ipr.gw_dns_types = append(ipr.gw_dns_types, dns.TypeAAAA)
	}
	if ipr.gw_ipver == 0 || ipr.gw_ipver == 4 {
		ipr.gw_dns_types = append(ipr.gw_dns_types, dns.TypeA)
	}

	mapper_name := "mappers"
	if ipr.mapper_socket != "" {
		mapper_name = "mapper-" + ipr.mapper_socket
	}
	ipr.mapper_socket = mapper_socket_dir + "/" + mapper_name + ".sock"

	ipr.m.init()

	return ipr, nil
}

func addrHasPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}
