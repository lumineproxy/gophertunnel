package xal

import (
	"context"
	"fmt"
	"sync"

	"github.com/df-mc/go-xsapi"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"golang.org/x/oauth2"
)

func RefreshTokenSource(underlying oauth2.TokenSource, authClient *authclient.AuthClient, relyingParty string) xsapi.TokenSource {
	return &refreshTokenSource{
		underlying:   underlying,
		AuthClient:   authClient,
		relyingParty: relyingParty,
	}
}

type refreshTokenSource struct {
	underlying oauth2.TokenSource

	// AuthClient is the client used to make requests to the Microsoft authentication servers. If nil,
	// auth.DefaultClient is used. This can be used to provide a timeout or proxy settings to the client.
	AuthClient   *authclient.AuthClient
	relyingParty string

	t  *oauth2.Token
	x  *auth.XBLToken
	mu sync.Mutex
}

func (r *refreshTokenSource) Token() (_ xsapi.Token, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.t == nil || !r.t.Valid() || r.x == nil {
		r.t, err = r.underlying.Token()
		if err != nil {
			return nil, fmt.Errorf("request underlying token: %w", err)
		}
		r.x, err = auth.RequestXBLToken(context.Background(), r.AuthClient, r.t, r.relyingParty)
		if err != nil {
			return nil, fmt.Errorf("request xbox live token: %w", err)
		}
	}
	return r.x, nil
}
