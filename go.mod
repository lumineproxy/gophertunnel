module github.com/sandertv/gophertunnel

go 1.24

require (
	github.com/coder/websocket v1.8.12
	github.com/df-mc/go-nethernet v0.0.0-20240902102242-528de5c8686f
	github.com/df-mc/go-playfab v0.0.0-20240902102459-2f8b5cd02173
	github.com/df-mc/go-xsapi v0.0.0-20240902102602-e7c4bffb955f
	github.com/go-gl/mathgl v1.1.0
	github.com/go-jose/go-jose/v4 v4.1.0
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.17.11
	github.com/muhammadmuzzammil1998/jsonc v1.0.0
	github.com/pelletier/go-toml v1.9.5
	github.com/pion/logging v0.2.2
	github.com/pion/webrtc/v4 v4.0.0-beta.29.0.20240826201411-3147b45f9db5
	github.com/sandertv/go-raknet v1.14.3-0.20250305181847-6af3e95113d6
	golang.org/x/net v0.35.0
	golang.org/x/oauth2 v0.23.0
	golang.org/x/text v0.22.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/image v0.17.0 // indirect
)

replace (
	github.com/df-mc/go-playfab => github.com/lactyy/go-playfab v0.0.0-20240911042657-037f6afe426f
	github.com/df-mc/go-xsapi => github.com/lactyy/go-xsapi v0.0.0-20240911052022-1b9dffef64ab
)
