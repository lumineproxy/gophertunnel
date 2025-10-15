package franchise

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/auth/franchise/internal"

	"github.com/google/uuid"
	"golang.org/x/text/language"
)

type Token struct {
	AuthorizationHeader string                   `json:"authorizationHeader"`
	ValidUntil          time.Time                `json:"validUntil"`
	Treatments          []string                 `json:"treatments"`
	Configurations      map[string]Configuration `json:"configurations"`
	TreatmentContext    string                   `json:"treatmentContext"`
}

const (
	ConfigurationMinecraft  = "minecraft"
	ConfigurationValidation = "validation"
)

// Token starts the session and returns the session token
func (conf TokenConfig) Token(ctx context.Context, c *authclient.AuthClient) (*Token, error) {
	if conf.Environment == nil {
		return nil, errors.New("minecraft/franchise: TokenConfig: Environment is nil")
	}
	u, err := url.Parse(conf.Environment.ServiceURI)
	if err != nil {
		return nil, fmt.Errorf("parse service URI: %w", err)
	}
	u = u.JoinPath("/api/v1.0/session/start")

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(conf); err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("make request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL, resp.Status)
	}

	var result internal.Result[*Token]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}
	if result.Data == nil {
		return nil, errors.New("minecraft/franchise: TokenConfig: result.Data is nil")
	}
	return result.Data, nil
}

type Configuration struct {
	ID         string            `json:"id"`
	Parameters map[string]string `json:"parameters"`
}

type AuthorizationEnvironment struct {
	ServiceURI        string `json:"serviceUri"`
	Issuer            string `json:"issuer"`
	PlayFabTitleID    string `json:"playFabTitleId"`
	EduPlayFabTitleID string `json:"eduPlayFabTitleId"`
}

func (*AuthorizationEnvironment) EnvironmentName() string { return "auth" }

type TokenConfigSource interface {
	TokenConfig() (*TokenConfig, error)
}

type TokenConfig struct {
	Device *DeviceConfig `json:"device,omitempty"`
	User   *UserConfig   `json:"user,omitempty"`

	Environment *AuthorizationEnvironment `json:"-"`
}

type DeviceConfig struct {
	ApplicationType    string    `json:"applicationType,omitempty"`
	Capabilities       []string  `json:"capabilities,omitempty"`
	GameVersion        string    `json:"gameVersion,omitempty"`
	ID                 uuid.UUID `json:"id,omitempty"`
	Memory             string    `json:"memory,omitempty"`
	Platform           string    `json:"platform,omitempty"`
	PlayFabTitleID     string    `json:"playFabTitleId,omitempty"`
	StorePlatform      string    `json:"storePlatform,omitempty"`
	TreatmentOverrides []string  `json:"treatmentOverrides,omitempty"`
	Type               string    `json:"type,omitempty"`
}

const (
	ApplicationTypeMinecraftPE = "MinecraftPE"

	CapabilityRayTracing = "RayTracing"

	PlatformWindows10 = "Windows10"

	StorePlatformUWPStore = "uwp.store"

	DeviceTypeWindows10 = "Windows10"
)

type UserConfig struct {
	Language     language.Tag `json:"language,omitempty"`
	LanguageCode language.Tag `json:"languageCode,omitempty"`
	RegionCode   string       `json:"regionCode,omitempty"`
	Token        string       `json:"token,omitempty"`
	TokenType    string       `json:"tokenType,omitempty"`
}

const TokenTypePlayFab = "PlayFab"
