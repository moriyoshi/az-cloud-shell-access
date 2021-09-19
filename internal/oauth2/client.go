package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// {
//   "token_endpoint": "https://login.windows.net/common/oauth2/v2.0/token",
//   "token_endpoint_auth_methods_supported": [
//     "client_secret_post",
//     "private_key_jwt",
//     "client_secret_basic"
//   ],
//   "jwks_uri": "https://login.windows.net/common/discovery/v2.0/keys",
//   "response_modes_supported": [
//     "query",
//     "fragment",
//     "form_post"
//   ],
//   "subject_types_supported": [
//     "pairwise"
//   ],
//   "id_token_signing_alg_values_supported": [
//     "RS256"
//   ],
//   "response_types_supported": [
//     "code",
//     "id_token",
//     "code id_token",
//     "id_token token"
//   ],
//   "scopes_supported": [
//     "openid",
//     "profile",
//     "email",
//     "offline_access"
//   ],
//   "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
//   "request_uri_parameter_supported": false,
//   "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
//   "authorization_endpoint": "https://login.windows.net/common/oauth2/v2.0/authorize",
//   "device_authorization_endpoint": "https://login.windows.net/common/oauth2/v2.0/devicecode",
//   "http_logout_supported": true,
//   "frontchannel_logout_supported": true,
//   "end_session_endpoint": "https://login.windows.net/common/oauth2/v2.0/logout",
//   "claims_supported": [
//     "sub",
//     "iss",
//     "cloud_instance_name",
//     "cloud_instance_host_name",
//     "cloud_graph_host_name",
//     "msgraph_host",
//     "aud",
//     "exp",
//     "iat",
//     "auth_time",
//     "acr",
//     "nonce",
//     "preferred_username",
//     "name",
//     "tid",
//     "ver",
//     "at_hash",
//     "c_hash",
//     "email"
//   ],
//   "kerberos_endpoint": "https://login.windows.net/common/kerberos",
//   "tenant_region_scope": null,
//   "cloud_instance_name": "microsoftonline.com",
//   "cloud_graph_host_name": "graph.windows.net",
//   "msgraph_host": "graph.microsoft.com",
//   "rbac_url": "https://pas.windows.net"
// }

type OpenIDConfiguration struct {
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	CloudGraphHostName                string   `json:"cloud_graph_host_name,omitempty"`
	CloudInstanceName                 string   `json:"cloud_instance_name,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	FrontchannelLogoutSupported       bool     `json:"frontchannel_logout_supported,omitempty"`
	HttpLogoutSupported               bool     `json:"http_logout_supported,omitempty"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	Issuer                            string   `json:"issuer,omitempty"`
	JwksUri                           string   `json:"jwks_uri,omitempty"`
	KerberosEndpoint                  string   `json:"kerberos_endpoint,omitempty"`
	MsgraphHost                       string   `json:"msgraph_host,omitempty"`
	RbacUrl                           string   `json:"rbac_url,omitempty"`
	RequestUriParameterSupported      bool     `json:"request_uri_parameter_supported,omitempty"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	TenantRegionScope                 string   `json:"tenant_region_scope,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
}

type TokenEndpointResponse struct {
	TokenType    string            `json:"token_type"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	IdToken      string            `json:"id_token,omitempty"`
	Scope        string            `json:"scope,omitempty"`
	ExpiresIn    DurationInSeconds `json:"expires_in,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Tokens struct {
	TokenType    string    `json:"tokenType"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	IdToken      string    `json:"idToken,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Resource     string    `json:"resource,omitempty"`
	ExpireOn     time.Time `json:"expireOn,omitempty"`
	Authority    string    `json:"_authority"`
}

func (creds *Tokens) Valid() bool {
	return creds.TokenType != "" && creds.AccessToken != ""
}

type TokenStore interface {
	Store(ctx context.Context, cred *Tokens) error
	Fetch(ctx context.Context) (*Tokens, error)
}

type Initiator interface {
	DisplayName() string
	Initiate(context.Context) (*Tokens, error)
}

type InitiatorFactory func(*Client) (Initiator, error)

type Client struct {
	Configuration OpenIDConfiguration
	Tx            *http.Transport
	ClientId      string
	Resource      string
	Scope         string
	TokenStore    TokenStore
	Flow          InitiatorFactory
	nowGetter     func() time.Time
	tokenMu       sync.Mutex
	cachedToken   *Tokens
}

func (c *Client) RefreshTokens(ctx context.Context, t *Tokens) (*Tokens, error) {
	nt := new(Tokens)
	*nt = *t

	var payload strings.Builder
	payload.WriteString("grant_type=refresh_token")
	payload.WriteString("&client_id=")
	payload.WriteString(url.QueryEscape(c.ClientId))
	payload.WriteString("&refresh_token=")
	payload.WriteString(url.QueryEscape(t.RefreshToken))
	if c.Resource != "" {
		payload.WriteString("&resource=")
		payload.WriteString(url.QueryEscape(c.Resource))
	}
	if c.Scope != "" {
		payload.WriteString("&scope=")
		payload.WriteString(url.QueryEscape(c.Scope))
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.Configuration.TokenEndpoint,
		strings.NewReader(payload.String()),
	)
	req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	if err != nil {
		return nil, err
	}

	hc := &http.Client{Transport: c.Tx}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if b, ok, err := readResponse(resp); !ok {
		if err != nil {
			return nil, err
		}
		var eresp ErrorResponse
		err = json.Unmarshal(b, &eresp)
		if err != nil {
			return nil, fmt.Errorf("endpoint %s returned status %d: %w: body: %s", req.URL.String(), resp.StatusCode, err, string(b))
		}
		return nil, fmt.Errorf("endpoint %s returned status %d, error: %s", req.URL.String(), resp.StatusCode, eresp.Error)
	} else {
		var tresp TokenEndpointResponse
		err = json.Unmarshal(b, &tresp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse response from endpoint %s: %w: body: %s", req.URL.String(), err, string(b))
		}
		expiry := c.nowGetter().Add(time.Duration(tresp.ExpiresIn))
		nt.TokenType = tresp.TokenType
		nt.AccessToken = tresp.AccessToken
		if tresp.RefreshToken != "" {
			nt.RefreshToken = tresp.RefreshToken
		}
		if tresp.IdToken != "" {
			nt.IdToken = tresp.IdToken
		}
		if tresp.Scope != "" {
			nt.Scope = tresp.Scope
		}
		nt.ExpireOn = expiry
	}
	return nt, nil
}

func (c *Client) FetchTokens(ctx context.Context, failOnRefreshFailure bool) (*Tokens, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	t := c.cachedToken
	var err error
	if t == nil {
		t, err = c.TokenStore.Fetch(ctx)
		if err != nil {
			return t, fmt.Errorf("failed to retrieve a credentials from store: %w", err)
		}
	}
	if t != nil && !t.ExpireOn.IsZero() && t.ExpireOn.After(c.nowGetter()) {
		return t, nil
	}

	if t != nil && t.RefreshToken != "" {
		t, err = c.RefreshTokens(ctx, t)
		if err != nil {
			if failOnRefreshFailure {
				return nil, fmt.Errorf("failed to refresh token: %w", err)
			} else {
				t = nil
			}
		}
	} else {
		t = nil
	}

	if t == nil {
		f, err := c.Flow(c)
		if err != nil {
			return nil, fmt.Errorf("failed to initiate token retrieval process: %w", err)
		}
		t, err = f.Initiate(ctx)
		if err != nil {
			return nil, fmt.Errorf("error occurred during token retrieval process by %s: %w", f.DisplayName(), err)
		}
	}
	c.cachedToken = t
	err = c.TokenStore.Store(ctx, t)
	if err != nil {
		return t, fmt.Errorf("failed to store a credentials to token store: %w", err)
	}
	return t, nil
}

type ClientOptionFunc func(*Client) (*Client, error)

func applyPlaceHoldersInner(s *string, placeholders map[string]string) {
	b := make([]byte, 0, len(*s))
	st := 0
	cs := 0
	for i, c := range *s {
		switch st {
		case 0:
			if c == '{' {
				b = append(b, (*s)[cs:i]...)
				st = 1
				cs = i + 1
			}
		case 1:
			if c == '}' {
				v, ok := placeholders[(*s)[cs:i]]
				if !ok {
					b = append(b, (*s)[cs-1:i+i]...)
				} else {
					b = append(b, v...)
				}
				cs = i + 1
				st = 0
			}
		}
	}
	if cs < len(*s) {
		b = append(b, (*s)[cs:]...)
	}
	*s = string(b)
}

func applyPlaceHolders(config *OpenIDConfiguration, placeholders map[string]string) {
	if placeholders == nil {
		return
	}
	applyPlaceHoldersInner(&config.AuthorizationEndpoint, placeholders)
	applyPlaceHoldersInner(&config.DeviceAuthorizationEndpoint, placeholders)
	applyPlaceHoldersInner(&config.EndSessionEndpoint, placeholders)
	applyPlaceHoldersInner(&config.KerberosEndpoint, placeholders)
	applyPlaceHoldersInner(&config.TokenEndpoint, placeholders)
	applyPlaceHoldersInner(&config.UserinfoEndpoint, placeholders)
}

func WithConfigurationFromWellknown(url string, placeholders map[string]string) ClientOptionFunc {
	return func(c *Client) (*Client, error) {
		resp, err := (&http.Client{Transport: c.Tx}).Get(url)
		if err != nil {
			return nil, err
		}
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("GET %s returned status code %d", url, resp.StatusCode)
		}
		err = json.NewDecoder(resp.Body).Decode(&c.Configuration)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
		applyPlaceHolders(&c.Configuration, placeholders)
		return c, nil
	}
}

func WithConfigurationOverrides(config OpenIDConfiguration) ClientOptionFunc {
	return func(c *Client) (*Client, error) {
		if config.AuthorizationEndpoint != "" {
			c.Configuration.AuthorizationEndpoint = config.AuthorizationEndpoint
		}
		if config.ClaimsSupported != nil {
			c.Configuration.ClaimsSupported = config.ClaimsSupported
		}
		if config.CloudGraphHostName != "" {
			c.Configuration.CloudGraphHostName = config.CloudGraphHostName
		}
		if config.CloudInstanceName != "" {
			c.Configuration.CloudInstanceName = config.CloudInstanceName
		}
		if config.DeviceAuthorizationEndpoint != "" {
			c.Configuration.DeviceAuthorizationEndpoint = config.DeviceAuthorizationEndpoint
		}
		if config.EndSessionEndpoint != "" {
			c.Configuration.EndSessionEndpoint = config.EndSessionEndpoint
		}
		if config.IdTokenSigningAlgValuesSupported != nil {
			c.Configuration.IdTokenSigningAlgValuesSupported = config.IdTokenSigningAlgValuesSupported
		}
		if config.Issuer != "" {
			c.Configuration.Issuer = config.Issuer
		}
		if config.JwksUri != "" {
			c.Configuration.JwksUri = config.JwksUri
		}
		if config.KerberosEndpoint != "" {
			c.Configuration.KerberosEndpoint = config.KerberosEndpoint
		}
		if config.MsgraphHost != "" {
			c.Configuration.MsgraphHost = config.MsgraphHost
		}
		if config.RbacUrl != "" {
			c.Configuration.RbacUrl = config.RbacUrl
		}
		if config.ResponseModesSupported != nil {
			c.Configuration.ResponseModesSupported = config.ResponseModesSupported
		}
		if config.ResponseTypesSupported != nil {
			c.Configuration.ResponseTypesSupported = config.ResponseTypesSupported
		}
		if config.ScopesSupported != nil {
			c.Configuration.ScopesSupported = config.ScopesSupported
		}
		if config.SubjectTypesSupported != nil {
			c.Configuration.SubjectTypesSupported = config.SubjectTypesSupported
		}
		if config.TenantRegionScope != "" {
			c.Configuration.TenantRegionScope = config.TenantRegionScope
		}
		if config.TokenEndpoint != "" {
			c.Configuration.TokenEndpoint = config.TokenEndpoint
		}
		if config.TokenEndpointAuthMethodsSupported != nil {
			c.Configuration.TokenEndpointAuthMethodsSupported = config.TokenEndpointAuthMethodsSupported
		}
		if config.UserinfoEndpoint != "" {
			c.Configuration.UserinfoEndpoint = config.UserinfoEndpoint
		}
		return c, nil
	}
}

func WithFlow(flow InitiatorFactory) ClientOptionFunc {
	return func(c *Client) (*Client, error) {
		c.Flow = flow
		return c, nil
	}
}

func WithResource(resource string) ClientOptionFunc {
	return func(c *Client) (*Client, error) {
		c.Resource = resource
		return c, nil
	}
}

func WithTokenStore(store TokenStore) ClientOptionFunc {
	return func(c *Client) (*Client, error) {
		c.TokenStore = store
		return c, nil
	}
}

func WithNowGetter(nowGetter func() time.Time) ClientOptionFunc {
	return func(c *Client) (*Client, error) {
		c.nowGetter = nowGetter
		return c, nil
	}
}

func NewClient(tx *http.Transport, clientId string, options ...ClientOptionFunc) (*Client, error) {
	c := &Client{
		Tx:        tx,
		ClientId:  clientId,
		nowGetter: time.Now,
	}
	var err error
	for _, o := range options {
		c, err = o(c)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}
