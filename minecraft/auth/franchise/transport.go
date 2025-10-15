package franchise

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
)

type Transport struct {
	IdentityProvider IdentityProvider
	Base             http.RoundTripper
	// AuthClient is the client used to make requests to the Microsoft authentication servers. If nil,
	// auth.DefaultClient is used. This can be used to provide a timeout or proxy settings to the client.
	AuthClient *authclient.AuthClient
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.AuthClient == nil {
		t.AuthClient = authclient.DefaultClient
	}
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				_ = req.Body.Close()
			}
		}()
	}

	if t.IdentityProvider == nil {
		return nil, errors.New("minecraft/franchise: Transport: IdentityProvider is nil")
	}
	config, err := t.IdentityProvider.TokenConfig()
	if err != nil {
		return nil, fmt.Errorf("request token config: %w", err)
	}
	token, err := config.Token(req.Context(), t.AuthClient)
	if err != nil {
		return nil, fmt.Errorf("request token: %w", err)
	}

	req2 := cloneRequest(req)
	token.SetAuthHeader(req2)

	reqBodyClosed = true
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
