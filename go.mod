module github.com/sandertv/gophertunnel

go 1.24.0

require (
	github.com/df-mc/jsonc v1.0.5
	github.com/coder/websocket v1.8.14
	github.com/df-mc/go-nethernet v0.0.0-20250326113854-da40ae9a1339
	github.com/df-mc/go-playfab v0.0.0-20240902102459-2f8b5cd02173
	github.com/df-mc/go-xsapi v0.0.0-20240902102602-e7c4bffb955f
	github.com/go-gl/mathgl v1.2.0
	github.com/go-jose/go-jose/v4 v4.1.2
	github.com/golang/snappy v1.0.0
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.18.0
	github.com/pelletier/go-toml v1.9.5
	github.com/sandertv/go-raknet v1.14.3-0.20250305181847-6af3e95113d6
	golang.org/x/net v0.44.0
	golang.org/x/oauth2 v0.31.0
	golang.org/x/text v0.29.0
)

require (
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v3 v3.0.7 // indirect
	github.com/pion/ice/v4 v4.0.10 // indirect
	github.com/pion/interceptor v0.1.40 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.15 // indirect
	github.com/pion/rtp v1.8.22 // indirect
	github.com/pion/sctp v1.8.39 // indirect
	github.com/pion/sdp/v3 v3.0.16 // indirect
	github.com/pion/srtp/v3 v3.0.7 // indirect
	github.com/pion/stun/v3 v3.0.0 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	github.com/pion/turn/v4 v4.1.1 // indirect
	github.com/pion/webrtc/v4 v4.1.4 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

replace (
	github.com/df-mc/go-playfab => github.com/lactyy/go-playfab v0.0.0-20240911042657-037f6afe426f
	github.com/df-mc/go-xsapi => github.com/lactyy/go-xsapi v0.0.0-20240911052022-1b9dffef64ab
)
