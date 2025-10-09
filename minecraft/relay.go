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

// Relay is a proxy that can be used to listen for incoming connections and forward them to a remote server.
type Relay struct {
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
	// OnDisconnect is called when either the client or server connection is closed. The function receives the
	// client connection, server connection, and a boolean indicating which connection was closed (true for client,
	// false for server).
	OnDisconnect func(client, server *Conn, clientDisconnected bool)

	l             *Listener
	listenNetwork string
}

// Listen starts listening for incoming connections on the given address.
func (r *Relay) Listen(network, address string) error {
	if r.Log == nil {
		r.Log = slog.New(internal.DiscardHandler{})
	}
	if r.Upstream == "" {
		return errors.New("proxy: upstream address not set")
	}

	var clientMu sync.Mutex
	var client *Conn

	serverDialer := r.ServerDialer
	serverDialer.AfterHandshake = func(server *Conn) error {
		server.SetDisablePacketHandling(true)

		clientMu.Lock()
		defer clientMu.Unlock()

		if r.OnStart != nil {
			r.OnStart(client, server)
		}

		var disconnectOnce sync.Once
		disconnect := func(clientDisconnected bool) {
			if r.OnDisconnect != nil {
				r.OnDisconnect(client, server, clientDisconnected)
			}
		}

		go r.forward(client, server, true, &disconnectOnce, disconnect)  // client->server direction
		go r.forward(server, client, false, &disconnectOnce, disconnect) // server->client direction
		return nil
	}

	cfg := r.ListenConfig
	userAfterHandshake := cfg.AfterHandshake
	cfg.AfterHandshake = func(c *Conn) error {
		c.SetDisablePacketHandling(true)

		clientMu.Lock()
		client = c
		clientMu.Unlock()

		go func() {
			d := serverDialer
			if !r.UseDialerData {
				d.ClientData = c.ClientData()
				d.IdentityData = c.IdentityData()
			}

			upstreamNetwork := r.UpstreamNetwork
			if upstreamNetwork == "" {
				upstreamNetwork = network
			}

			var err error
			if r.DialContext != nil {
				_, err = d.DialHandshakeContext(r.DialContext, upstreamNetwork, r.Upstream)
			} else {
				_, err = d.DialHandshake(upstreamNetwork, r.Upstream)
			}
			if err != nil {
				r.Log.Error("proxy: dial upstream", "error", err)
				_ = r.l.Disconnect(c, fmt.Sprintf("Unable to connect to upstream server: %v", err))
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
	r.l = l
	r.listenNetwork = network
	return nil
}

// Close closes the proxy listener.
func (r *Relay) Close() error {
	if r.l == nil {
		return nil
	}
	return r.l.Close()
}

// forward forwards packets from one connection to another.
func (r *Relay) forward(src, dst *Conn, isClientToServer bool, disconnectOnce *sync.Once, disconnect func(bool)) {
	defer src.Close()
	defer dst.Close()
	for {
		pk, err := src.ReadPacket()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				r.Log.Error("proxy: read packet", "error", err)
			}
			// If this error is a DisconnectError, tell the listener to disconnect the other connection with the message.
			var disc DisconnectError
			if ok := errors.As(err, &disc); ok && r.l != nil {
				_ = r.l.Disconnect(dst, disc.Error())
			}
			// Call OnDisconnect callback when connection is closed (only once)
			disconnectOnce.Do(func() {
				disconnect(isClientToServer)
			})
			return
		}
		if r.OnPacket != nil {
			if err := r.OnPacket(pk, src, dst); err != nil {
				if !errors.Is(err, io.EOF) {
					r.Log.Error("proxy: handle packet", "error", err)
				}
				continue
			}
		}
		if err := dst.WritePacket(pk); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				r.Log.Error("proxy: write packet", "error", err)
			}
			// If this error is a DisconnectError, tell the listener to disconnect the other connection with the message.
			var disc DisconnectError
			if ok := errors.As(err, &disc); ok && r.l != nil {
				_ = r.l.Disconnect(src, disc.Error())
			}
			// Call OnDisconnect callback when connection is closed (only once)
			disconnectOnce.Do(func() {
				disconnect(isClientToServer)
			})
			return
		}
	}
}
