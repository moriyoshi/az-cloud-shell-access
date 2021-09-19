package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skratchdot/open-golang/open"
)

// https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-oauth2-device-code

type Prompter func(msg string) error

type DeviceCodeFlowInitiator struct {
	c                   *Client
	tokenRequestBuilder func(context.Context, *OpenIDConfiguration, string, string, string) (*http.Request, error)
	prompter            Prompter
}

func (*DeviceCodeFlowInitiator) DisplayName() string {
	return "device code flow"
}

// {
//   "user_code": "XXXXXXXXX",
//   "XXXXXX_XXXX": "XXXXXXXXXXXX--XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
//   "verification_url": "https://microsoft.com/devicelogin",
//   "expires_in": "900",
//   "interval": "5",
//   "message": "To sign in, use a web browser to open the page "
// }
type deviceCodeFlowResponse struct {
	UserCode        string            `json:"user_code"`
	DeviceCode      string            `json:"device_code"`
	VerificationUrl string            `json:"verification_url,omitempty"`
	VerificationUri string            `json:"verification_uri,omitempty"`
	ExpiresIn       DurationInSeconds `json:"expires_in"`
	Interval        DurationInSeconds `json:"interval"`
	Message         string            `json:"message"`
}

func buildRequestForDeviceCodeFlow(ctx context.Context, config *OpenIDConfiguration, clientId string, resource string, scope string) (*http.Request, error) {
	var payload strings.Builder
	payload.WriteString("client_id=")
	payload.WriteString(url.QueryEscape(clientId))
	if resource != "" {
		payload.WriteString("&resource=")
		payload.WriteString(url.QueryEscape(resource))
	}
	if scope != "" {
		payload.WriteString("&scope=")
		payload.WriteString(url.QueryEscape(scope))
	}
	return http.NewRequestWithContext(ctx, "POST", config.DeviceAuthorizationEndpoint, strings.NewReader(payload.String()))
}

func buildRequestForTokenEndpointDeviceCodeFlow(ctx context.Context, config *OpenIDConfiguration, clientId string, deviceCode string, resource string) (*http.Request, error) {
	var payload strings.Builder
	payload.WriteString("grant_type=urn:ietf:params:oauth:grant-type:device_code")
	payload.WriteString("&client_id=")
	payload.WriteString(url.QueryEscape(clientId))
	payload.WriteString("&device_code=")
	payload.WriteString(url.QueryEscape(deviceCode))
	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenEndpoint, strings.NewReader(payload.String()))
	if err != nil {
		return nil, err
	}
	req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	return req, nil
}

func buildRequestForTokenEndpointLegacyDeviceCodeFlow(ctx context.Context, config *OpenIDConfiguration, clientId string, deviceCode string, resource string) (*http.Request, error) {
	var payload strings.Builder
	payload.WriteString("grant_type=device_code")
	payload.WriteString("&client_id=")
	payload.WriteString(url.QueryEscape(clientId))
	if resource != "" {
		payload.WriteString("&resource=")
		payload.WriteString(url.QueryEscape(resource))
	}
	payload.WriteString("&code=")
	payload.WriteString(url.QueryEscape(deviceCode))
	req, err := http.NewRequestWithContext(ctx, "POST", config.TokenEndpoint, strings.NewReader(payload.String()))
	if err != nil {
		return nil, err
	}
	req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	return req, nil
}

func (i *DeviceCodeFlowInitiator) poll(ctx context.Context, hc *http.Client, dresp *deviceCodeFlowResponse) (TokenEndpointResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	t := time.NewTimer(time.Duration(dresp.ExpiresIn))
	defer t.Stop()
	go func() {
		<-t.C
		cancel()
	}()

outer:
	for {
		req, err := i.tokenRequestBuilder(ctx, &i.c.Configuration, i.c.ClientId, dresp.DeviceCode, i.c.Resource)
		if err != nil {
			return TokenEndpointResponse{}, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return TokenEndpointResponse{}, fmt.Errorf("failed to make a request to endpoint %s: %w", req.URL.String(), err)
		}
		if b, ok, err := readResponse(resp); ok {
			var tresp TokenEndpointResponse
			err = json.Unmarshal(b, &tresp)
			if err != nil {
				return tresp, fmt.Errorf("failed to parse response from endpoint %s: %w: body: %s", req.URL.String(), err, string(b))
			}
			return tresp, nil
		} else {
			if err != nil {
				return TokenEndpointResponse{}, err
			}
			var eresp ErrorResponse
			err = json.Unmarshal(b, &eresp)
			if err != nil {
				return TokenEndpointResponse{}, fmt.Errorf("endpoint %s returned status %d: %w: body: %s", req.URL.String(), resp.StatusCode, err, string(b))
			}
			if eresp.Error != "authorization_pending" {
				return TokenEndpointResponse{}, fmt.Errorf("endpoint %s returned status %d, error: %s", req.URL.String(), resp.StatusCode, eresp.Error)
			}
		}
		it := time.NewTimer(time.Duration(dresp.Interval))
		select {
		case <-it.C:
			continue
		case <-ctx.Done():
			it.Stop()
			break outer
		}
	}
	return TokenEndpointResponse{}, fmt.Errorf("operation did not complete in %s", time.Duration(dresp.ExpiresIn).String())
}

func (i *DeviceCodeFlowInitiator) Initiate(ctx context.Context) (*Tokens, error) {
	hc := &http.Client{Transport: i.c.Tx}
	dresp, err := func() (*deviceCodeFlowResponse, error) {
		req, err := buildRequestForDeviceCodeFlow(ctx, &i.c.Configuration, i.c.ClientId, i.c.Resource, i.c.Scope)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve device code and user code: %w", err)
		}
		if b, ok, err := readResponse(resp); !ok {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("failed to retrieve device code and user code; endpoint %s returned status %d, body: %s", req.URL.String(), resp.StatusCode, string(b))
		} else {
			var dresp deviceCodeFlowResponse
			err = json.Unmarshal(b, &dresp)
			if err != nil {
				return nil, err
			}
			return &dresp, nil
		}
	}()
	if err != nil {
		return nil, err
	}
	verificationUri := dresp.VerificationUri
	if verificationUri == "" {
		verificationUri = dresp.VerificationUrl
	}
	err = i.prompter(dresp.Message)
	if err != nil {
		return nil, err
	}
	_ = open.Run(verificationUri)
	tresp, err := i.poll(ctx, hc, dresp)
	if err != nil {
		return nil, fmt.Errorf("error occurred during polling for user interaction: %w", err)
	}
	expiry := i.c.nowGetter().Add(time.Duration(tresp.ExpiresIn))
	return &Tokens{
		TokenType:    tresp.TokenType,
		AccessToken:  tresp.AccessToken,
		RefreshToken: tresp.RefreshToken,
		IdToken:      tresp.IdToken,
		Scope:        tresp.Scope,
		ExpireOn:     expiry,
	}, nil
}

func NewDeviceCodeFlow(prompter Prompter) func(c *Client) (Initiator, error) {
	return func(c *Client) (Initiator, error) {
		return &DeviceCodeFlowInitiator{
			c:                   c,
			tokenRequestBuilder: buildRequestForTokenEndpointDeviceCodeFlow,
			prompter:            prompter,
		}, nil
	}
}

func NewLegacyDeviceCodeFlow(prompter Prompter) func(c *Client) (Initiator, error) {
	return func(c *Client) (Initiator, error) {
		return &DeviceCodeFlowInitiator{
			c:                   c,
			tokenRequestBuilder: buildRequestForTokenEndpointLegacyDeviceCodeFlow,
			prompter:            prompter,
		}, nil
	}
}
