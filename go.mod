module github.com/sandertv/gophertunnel

go 1.24.0

require (
	github.com/coder/websocket v1.8.14
	github.com/df-mc/go-nethernet v0.0.0-20250326113854-da40ae9a1339
	github.com/df-mc/go-playfab v0.0.0-20240902102459-2f8b5cd02173
	github.com/df-mc/go-xsapi v0.0.0-20240902102602-e7c4bffb955f
	github.com/df-mc/jsonc v1.0.5
	github.com/go-gl/mathgl v1.2.0
	github.com/go-jose/go-jose/v4 v4.1.3
	github.com/golang/snappy v1.0.0
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.18.0
	github.com/pelletier/go-toml v1.9.5
	github.com/sandertv/go-raknet v1.14.3-0.20250823121252-325aeea25d25
	golang.org/x/net v0.46.0
	golang.org/x/oauth2 v0.32.0
	golang.org/x/text v0.30.0
)

require (
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v3 v3.0.7 // indirect
	github.com/pion/ice/v4 v4.0.10 // indirect
	github.com/pion/interceptor v0.1.41 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.15 // indirect
	github.com/pion/rtp v1.8.23 // indirect
	github.com/pion/sctp v1.8.39 // indirect
	github.com/pion/sdp/v3 v3.0.16 // indirect
	github.com/pion/srtp/v3 v3.0.8 // indirect
	github.com/pion/stun/v3 v3.0.0 // indirect
	github.com/pion/transport/v3 v3.0.8 // indirect
	github.com/pion/turn/v4 v4.1.1 // indirect
	github.com/pion/webrtc/v4 v4.1.5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

replace (
	github.com/df-mc/go-nethernet => github.com/lumineproxy/go-nethernet v0.0.0-20251024044000-f3860133179b
	github.com/df-mc/go-playfab => github.com/lactyy/go-playfab v0.0.0-20240911042657-037f6afe426f
	github.com/df-mc/go-xsapi => github.com/lactyy/go-xsapi v0.0.0-20240911052022-1b9dffef64ab
)
