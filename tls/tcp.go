package tls

import (
	"crypto/tls"

	tcp "github.com/mrhaoxx/OpenNG/tcp"
)

func (mgr *TlsMgr) Handle(c *tcp.Conn) tcp.SerRet {
	hellov, ok := c.Load(tcp.KeyTLS)
	hello := hellov.(*tls.ClientHelloInfo)

	if mgr.snis != nil && !mgr.snis.MatchString(hello.ServerName) {
		return tcp.Continue
	}

	cert := mgr.getCertificate(hello.ServerName)
	if cert != nil {
		if !ok || len(hello.SupportedProtos) == 0 {
			ts := tls.Server(c.TopConn(), &tls.Config{
				Certificates: []tls.Certificate{*cert},
			})
			err := ts.Handshake()
			if err != nil {
				return tcp.Close
			}
			c.Upgrade(ts, "")
			return tcp.Continue
		} else {
			for _, sp := range hello.SupportedProtos {
				switch sp {
				case "http/1.1":
					c.Upgrade(tls.Server(c.TopConn(), &tls.Config{
						Certificates: []tls.Certificate{*cert},
						NextProtos:   []string{sp},
					}), "HTTP1")
					return tcp.Upgrade
				case "h2":
					// Skip h2: HTTP/2 WebSocket uses Extended CONNECT (RFC 8441)
					// which we don't proxy, and our reverse proxy only detects
					// HTTP/1.1 Upgrade. Force http/1.1 so WebSocket upgrade works.
					continue
				default:
					c.Store(tcp.KeyTLS, sp)
					continue
				}
			}

			c.Upgrade(tls.Server(c.TopConn(), &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}), "")

			return tcp.Continue
		}
	}
	return tcp.Close
}
