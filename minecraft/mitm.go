package minecraft

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// MITM is a proxy that can be used to listen for incoming connections and forward them to a remote server.
type MITM struct {
	// Log is a logger that will be used to log errors. If nil, a new logger will be created.
	Log *slog.Logger

	// ListenConfig is the configuration for the listener that accepts client connections.
	ListenConfig ListenConfig

	// ServerDialer is the dialer that will be used to connect to the server. The TokenSource should be set here for
	// authentication. If UseDialerData is true, the ClientData and IdentityData from this dialer will be used.
	ServerDialer Dialer
	// UseDialerData, if true, causes the proxy to use the ClientData and IdentityData from the ServerDialer
	// field, rather than the data from the connecting client.
	UseDialerData bool

	// UpstreamNetwork is the network type of the upstream server, for example "raknet". If empty, the listener's
	// network type is used.
	UpstreamNetwork string
	// Upstream is the address of the server to which the proxy will connect.
	Upstream string

	// DialContext, if not nil, provides the context for dialing the upstream server.
	// If nil, a default context with a 30-second timeout is used.
	DialContext context.Context

	// OnStart is called when a new client has connected and a connection to the upstream server has been established.
	// It provides access to both connection objects.
	OnStart func(client, server *Conn)
	// OnPacket is a function that is called for each packet that is sent from the client to the server and from
	// the server to the client. It can be used to modify or cancel the packet. Returning an error will cause the
	// packet to not be forwarded. If the error is io.EOF, the packet is silently dropped.
	OnPacket func(p packet.Packet, src, dst *Conn) error

	l             *Listener
	listenNetwork string
}

// Listen starts listening for incoming connections on the given address.
func (p *MITM) Listen(network, address string) error {
	if p.Log == nil {
		p.Log = slog.New(internal.DiscardHandler{})
	}
	if p.Upstream == "" {
		return errors.New("proxy: upstream address not set")
	}

	var clientMu sync.Mutex
	var client *Conn

	serverDialer := p.ServerDialer
	serverDialer.AfterHandshake = func(server *Conn) error {
		server.SetDisablePacketHandling(true)

		clientMu.Lock()
		defer clientMu.Unlock()

		if p.OnStart != nil {
			p.OnStart(client, server)
		}

		go p.forward(client, server)
		go p.forward(server, client)
		return nil
	}

	cfg := p.ListenConfig
	userAfterHandshake := cfg.AfterHandshake
	cfg.AfterHandshake = func(c *Conn) error {
		c.SetDisablePacketHandling(true)

		clientMu.Lock()
		client = c
		clientMu.Unlock()

		go func() {
			d := serverDialer
			if !p.UseDialerData {
				d.ClientData = c.ClientData()
				d.IdentityData = c.IdentityData()
			}

			upstreamNetwork := p.UpstreamNetwork
			if upstreamNetwork == "" {
				upstreamNetwork = network
			}

			var err error
			if p.DialContext != nil {
				_, err = d.DialHandshakeContext(p.DialContext, upstreamNetwork, p.Upstream)
			} else {
				_, err = d.DialHandshake(upstreamNetwork, p.Upstream)
			}
			if err != nil {
				p.Log.Error("proxy: dial upstream", "error", err)
				_ = p.l.Disconnect(c, fmt.Sprintf("Unable to connect to upstream server: %v", err))
			}
		}()

		if userAfterHandshake != nil {
			return userAfterHandshake(c)
		}
		return nil
	}

	l, err := cfg.Listen(network, address)
	if err != nil {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	p.l = l
	p.listenNetwork = network
	return nil
}

// Close closes the proxy listener.
func (p *MITM) Close() error {
	if p.l == nil {
		return nil
	}
	return p.l.Close()
}

// forward forwards packets from one connection to another.
func (p *MITM) forward(src, dst *Conn) {
	defer src.Close()
	defer dst.Close()
	for {
		pk, err := src.ReadPacket()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				p.Log.Error("proxy: read packet", "error", err)
			}
			return
		}
		if p.OnPacket != nil {
			if err := p.OnPacket(pk, src, dst); err != nil {
				if !errors.Is(err, io.EOF) {
					p.Log.Error("proxy: handle packet", "error", err)
				}
				continue
			}
		}
		if err := dst.WritePacket(pk); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				p.Log.Error("proxy: write packet", "error", err)
			}
			return
		}
	}
}
