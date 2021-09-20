package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/moriyoshi/az-cloud-shell-access/internal/oauth2"
)

type TokenFetcher func() (*oauth2.Tokens, error)

type CloudConsole struct {
	baseUrl      string
	hc           *http.Client
	wsDialer     *websocket.Dialer
	tokenFetcher TokenFetcher
	nowGetter    func() time.Time
}

type ReadWriterWithTermInfo interface {
	io.ReadWriter
	ScreenSize() (int, int, error)
	MakeRaw() (interface{}, error)
	Restore(interface{}) error
	SetReadDeadline(time.Time) error
}

type CloudConsoleSettings struct {
	PreferredOsType    string `json:"preferredOsType"`
	PreferredLocation  string `json:"preferredLocation"`
	PreferredShellType string `json:"preferredShellType"`
	StorageProfile     struct {
		StorageAccountResourceId string `json:"storageAccountResourceId"`
		FileShareName            string `json:"fileShareName"`
		DiskSizeInGB             int    `json:"diskSizeInG"`
	} `json:"storageProfile"`
	TerminalSettings struct {
		FontSize  string `json:"fontSize"`  // "Small", "Large", ...
		FontStyle string `json:"fontStyle"` // "Monospace", "Consolas", ...
	} `json:"terminalSettings"`
	VnetSettings struct {
		NetworkProfileResourceId string `json:"networkProfileResourceId"`
		RelayNamespaceResourceId string `json:"relayNamespaceResourceId"`
		IsolatedStorageProfile   struct {
			StorageAccountResourceId string `json:"storageAccountResourceId"`
			FileShareName            string `json:"fileShareName"`
			DiskSizeInGB             int    `json:"diskSizeInGB"`
		} `json:"isolatedStorageProfile"`
		Location string `json:"location"`
	} `json:"vnetSettings"`
	NetworkType string `json:"networkType"` // "Isolated"
}

func buildRequestGetCloudConsoleUserSettings(ctx context.Context, t *oauth2.Tokens, baseUrl string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		baseUrl+"/providers/Microsoft.Portal/userSettings/cloudconsole?api-version=2020-04-01-preview",
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header["Authorization"] = []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}
	return req, nil
}

func (cc *CloudConsole) getCloudConsoleSettings(ctx context.Context) (*CloudConsoleSettings, error) {
	t, err := cc.tokenFetcher()
	if err != nil {
		return nil, err
	}
	req, err := buildRequestGetCloudConsoleUserSettings(ctx, t, cc.baseUrl)
	if err != nil {
		return nil, err
	}
	resp, err := cc.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if b, ok, err := readResponse(resp); !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("endpoint %s returned status code %d", req.URL.String(), resp.StatusCode)
	} else {
		var ccs struct {
			Properties CloudConsoleSettings `json:"properties"`
		}
		err = json.Unmarshal(b, &ccs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse response as JSON: %w: %s", err, string(b))
		}
		return &ccs.Properties, nil
	}
}

type ConsoleSession struct {
	OsType            string `json:"osType"`
	ProvisioningState string `json:"provisioningState"`
	Uri               string `json:"uri"`
}

func buildRequestInitiateConsoleSession(ctx context.Context, t *oauth2.Tokens, baseUrl string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		"PUT",
		baseUrl+"/providers/Microsoft.Portal/consoles/default?api-version=2020-04-01-preview",
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header["Authorization"] = []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}
	return req, nil
}

func (cc *CloudConsole) waitForProvisionCompleted(ctx context.Context, ccs *CloudConsoleSettings) (*ConsoleSession, error) {
	t, err := cc.tokenFetcher()
	if err != nil {
		return nil, err
	}
	req, err := buildRequestInitiateConsoleSession(ctx, t, cc.baseUrl)
	if err != nil {
		return nil, err
	}

	tm := time.NewTimer(time.Duration(600) * time.Second)
	for {
		var cs struct {
			Properties ConsoleSession `json:"properties"`
		}
		phc := &PollingHttpClient{Transport: cc.hc.Transport}
		resp, err := phc.Do(req)
		if err != nil {
			return nil, err
		}
		if b, ok, err := readResponse(resp); !ok {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("endpoint %s returned status code %d", req.URL.String(), resp.StatusCode)
		} else {
			err = json.Unmarshal(b, &cs)
			if err != nil {
				return nil, fmt.Errorf("failed to parse response as JSON: %w: %s", err, string(b))
			}
			switch cs.Properties.ProvisioningState {
			case "Failed":
				return nil, fmt.Errorf("provisioning failed")
			case "Succeeded":
				return &cs.Properties, nil
			}
			it := time.NewTimer(30 * time.Second)
			select {
			case <-tm.C:
				it.Stop()
				return nil, fmt.Errorf("provisioning not completed within the timeout value")
			case <-ctx.Done():
				it.Stop()
				return nil, fmt.Errorf("operation canceled")
			case <-it.C:
			}
		}
	}
}

func buildServiceBusOpenRequest(ctx context.Context, t *oauth2.Tokens, uri string, cols, rows int, shellType string) (*http.Request, error) {
	_uri, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	_uri.Path = strings.TrimRight(_uri.Path, "/") + "/terminals"
	if _uri.RawQuery != "" {
		_uri.RawQuery += "&"
	}
	_uri.RawQuery += fmt.Sprintf(
		"version=2019-01-01&cols=%d&rows=%d&shell=%s",
		cols,
		rows,
		url.QueryEscape(shellType),
	)
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		_uri.String(),
		strings.NewReader("{}"),
	)
	if err != nil {
		return nil, err
	}
	req.Header["Origin"] = []string{"https://ux.console.azure.com"}
	req.Header["Referer"] = []string{"https://ux.console.azure.com/"}
	req.Header["Content-Type"] = []string{"application/json"}
	req.Header["Authorization"] = []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}
	return req, nil
}

type ServiceBusEndpointDescriptor struct {
	Id            string                   `json:"id"`
	SocketUri     string                   `json:"socketUri"`
	IdleTimeout   oauth2.DurationInSeconds `json:"idleTimeout"`
	TokenUpdated  bool                     `json:"tokenUpdated"`
	RootDirectroy string                   `json:"rootDirectory"`
}

func (cc *CloudConsole) openServiceBus(ctx context.Context, uri string, shellType string, rw ReadWriterWithTermInfo) (*ServiceBusEndpointDescriptor, error) {
	t, err := cc.tokenFetcher()
	if err != nil {
		return nil, err
	}
	cols, rows, err := rw.ScreenSize()
	if err != nil {
		return nil, err
	}
	req, err := buildServiceBusOpenRequest(ctx, t, uri, cols, rows, shellType)
	if err != nil {
		return nil, err
	}
	resp, err := cc.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if b, ok, err := readResponse(resp); !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("endpoint %s returned status code %d: %s", req.URL.String(), resp.StatusCode, string(b))
	} else {
		var sed ServiceBusEndpointDescriptor
		err = json.Unmarshal(b, &sed)
		if err != nil {
			return nil, fmt.Errorf("failed to parse response as JSON: %w: %s", err, string(b))
		}
		return &sed, nil
	}
}

type ServiceBusAuthorizationResponse struct {
	Token string `json:"token"`
}

func buildServiceBusAuthorizationRequest(ctx context.Context, t *oauth2.Tokens, uri string) (*http.Request, error) {
	_uri, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	_uri.Path = strings.TrimRight(_uri.Path, "/") + "/authorize"
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		_uri.String(),
		strings.NewReader("{}"),
	)
	if err != nil {
		return nil, err
	}
	req.Header["Origin"] = []string{"https://ux.console.azure.com"}
	req.Header["Referer"] = []string{"https://ux.console.azure.com/"}
	req.Header["Content-Type"] = []string{"application/json"}
	req.Header["Authorization"] = []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}
	return req, nil
}

func (cc *CloudConsole) authorizeServiceBus(ctx context.Context, uri string) (*ServiceBusAuthorizationResponse, error) {
	t, err := cc.tokenFetcher()
	if err != nil {
		return nil, err
	}
	req, err := buildServiceBusAuthorizationRequest(ctx, t, uri)
	if err != nil {
		return nil, err
	}
	resp, err := cc.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if b, ok, err := readResponse(resp); !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("endpoint %s returned status code %d", req.URL.String(), resp.StatusCode)
	} else {
		var sar ServiceBusAuthorizationResponse
		err = json.Unmarshal(b, &sar)
		if err != nil {
			return nil, fmt.Errorf("failed to parse response as JSON: %w: %s", err, string(b))
		}
		return &sar, nil
	}
}

func synthesizeWebSocketUriIsolated(_url *url.URL, sed *ServiceBusEndpointDescriptor, suffix string) (string, error) {
	retval := *_url
	switch retval.Scheme {
	case "http":
		retval.Scheme = "ws"
	case "https":
		retval.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported scheme: %s", retval.Scheme)
	}
	retval.Path = fmt.Sprintf("/$hc%s/terminals/%s%s", retval.Path, sed.Id, suffix)
	return retval.String(), nil
}

func (cc *CloudConsole) openWsChannelsIsolated(ctx context.Context, cs *ConsoleSession, sed *ServiceBusEndpointDescriptor) (*websocket.Conn, *websocket.Conn, error) {
	t, err := cc.tokenFetcher()
	if err != nil {
		return nil, nil, err
	}
	_url, err := url.Parse(cs.Uri)
	if err != nil {
		return nil, nil, err
	}
	wsUriData, err := synthesizeWebSocketUriIsolated(_url, sed, "")
	if err != nil {
		return nil, nil, err
	}
	// wsUriCtrl, err := synthesizeWebSocketUriIsolated(_url, sed, "/control")
	// if err != nil {
	// 	return nil, nil, err
	// }
	h := http.Header{"Authorization": []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}}
	wsData, _, err := cc.wsDialer.DialContext(ctx, wsUriData, h)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to establish a data channel: %w", err)
	}
	// From what I learnt from the source code of Windows Terminal,
	// control channel is not necessary for normal operation.
	// wsCtrl, resp, err := websocket.DialContext(ctx, wsUriData, h)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to establish a icontrol channel: %w", err)
	// }
	return wsData, nil, nil
}

func (cc *CloudConsole) openWsChannelsPublic(ctx context.Context, cs *ConsoleSession, sed *ServiceBusEndpointDescriptor) (*websocket.Conn, *websocket.Conn, error) {
	t, err := cc.tokenFetcher()
	if err != nil {
		return nil, nil, err
	}
	h := http.Header{"Authorization": []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}}
	wsData, _, err := cc.wsDialer.DialContext(ctx, sed.SocketUri, h)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to establish a data channel: %w", err)
	}
	// From what I learnt from the source code of Windows Terminal,
	// control channel is not necessary for normal operation.
	// wsCtrl, resp, err := websocket.DialContext(ctx, sed.SocketUri + "/control", h)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to establish a icontrol channel: %w", err)
	// }
	return wsData, nil, nil
}

var longLongAgo = time.Unix(0, 0)

func buildScreenSizeChangeRequest(ctx context.Context, t *oauth2.Tokens, uri string, sed *ServiceBusEndpointDescriptor, cols, rows int) (*http.Request, error) {
	_uri, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	_uri.Path = strings.TrimRight(_uri.Path, "/") + fmt.Sprintf("/terminals/%s/size", url.PathEscape(sed.Id))
	if _uri.RawQuery != "" {
		_uri.RawQuery += "&"
	}
	_uri.RawQuery += fmt.Sprintf(
		"version=2019-01-01&cols=%d&rows=%d",
		cols,
		rows,
	)
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		_uri.String(),
		strings.NewReader("{}"),
	)
	if err != nil {
		return nil, err
	}
	req.Header["Origin"] = []string{"https://ux.console.azure.com"}
	req.Header["Referer"] = []string{"https://ux.console.azure.com/"}
	req.Header["Content-Type"] = []string{"application/json"}
	req.Header["Authorization"] = []string{fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)}
	return req, nil
}

func (cc *CloudConsole) notifyScreenSizeChange(ctx context.Context, uri string, sed *ServiceBusEndpointDescriptor, rw ReadWriterWithTermInfo) error {
	t, err := cc.tokenFetcher()
	if err != nil {
		return err
	}
	cols, rows, err := rw.ScreenSize()
	if err != nil {
		return err
	}
	req, err := buildScreenSizeChangeRequest(ctx, t, uri, sed, cols, rows)
	if err != nil {
		return err
	}
	resp, err := cc.hc.Do(req)
	if err != nil {
		return err
	}
	if b, ok, err := readResponse(resp); !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("endpoint %s returned status code %d: %s", req.URL.String(), resp.StatusCode, string(b))
	} else {
		return nil
	}
}

func (cc *CloudConsole) interact(ctx context.Context, wsData *websocket.Conn, wsCtrl *websocket.Conn, uri string, sed *ServiceBusEndpointDescriptor, rw ReadWriterWithTermInfo) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	tt, err := rw.MakeRaw()
	if err != nil {
		return err
	}

	defer rw.Restore(tt) //nolint:errcheck

	sigCh := make(chan os.Signal, 1024)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		signal.Stop(sigCh)
		close(sigCh)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			_, b, err := wsData.ReadMessage()
			if err != nil {
				return
			}
			n, err := rw.Write(b)
			if err != nil {
				return
			}
			if n != len(b) {
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		b := make([]byte, 131072)
		for {
			n, err := rw.Read(b)
			if err != nil {
				return
			}
			err = wsData.WriteMessage(
				websocket.BinaryMessage,
				b[:n],
			)
			if err != nil {
				return
			}
		}
	}()
	var winchFlag uintptr
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		t := time.NewTicker(time.Second)
		defer t.Stop()
	outer:
		for {
			select {
			case <-ctx.Done():
				break outer
			case <-t.C:
				if atomic.CompareAndSwapUintptr(&winchFlag, 1, 0) {
					if cc.notifyScreenSizeChange(ctx, uri, sed, rw) != nil {
						break outer
					}
				}
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
	outer:
		for sig := range sigCh {
			switch sig {
			case syscall.SIGINT:
				wsData.SetReadDeadline(longLongAgo)                   //nolint: errcheck
				rw.SetReadDeadline(longLongAgo)                       //nolint: errcheck
				wsData.WriteMessage(websocket.CloseMessage, []byte{}) //nolint: errcheck
			case syscall.SIGTERM:
				wsData.SetReadDeadline(longLongAgo) //nolint: errcheck
				rw.SetReadDeadline(longLongAgo)     //nolint: errcheck
				break outer
			case syscall.SIGWINCH:
				atomic.StoreUintptr(&winchFlag, 1)
			}
		}
	}()
	wg.Wait()
	return nil
}

func (cc *CloudConsole) startIsolated(ctx context.Context, ccs *CloudConsoleSettings, rw ReadWriterWithTermInfo) error {
	cs, err := cc.waitForProvisionCompleted(ctx, ccs)
	if err != nil {
		return err
	}
	_, err = cc.authorizeServiceBus(ctx, cs.Uri)
	if err != nil {
		return err
	}
	sed, err := cc.openServiceBus(ctx, cs.Uri, ccs.PreferredShellType, rw)
	if err != nil {
		return err
	}
	wsData, wsCtrl, err := cc.openWsChannelsIsolated(ctx, cs, sed)
	if err != nil {
		return err
	}
	defer func() {
		if wsData != nil {
			wsData.Close()
		}
		if wsCtrl != nil {
			wsCtrl.Close()
		}
	}()
	return cc.interact(ctx, wsData, wsCtrl, cs.Uri, sed, rw)
}

func (cc *CloudConsole) startPublic(ctx context.Context, ccs *CloudConsoleSettings, rw ReadWriterWithTermInfo) error {
	cs, err := cc.waitForProvisionCompleted(ctx, ccs)
	if err != nil {
		return err
	}
	_, err = cc.authorizeServiceBus(ctx, cs.Uri)
	if err != nil {
		return err
	}
	sed, err := cc.openServiceBus(ctx, cs.Uri, ccs.PreferredShellType, rw)
	if err != nil {
		return err
	}
	wsData, wsCtrl, err := cc.openWsChannelsPublic(ctx, cs, sed)
	if err != nil {
		return err
	}
	defer func() {
		if wsData != nil {
			wsData.Close()
		}
		if wsCtrl != nil {
			wsCtrl.Close()
		}
	}()
	return cc.interact(ctx, wsData, wsCtrl, cs.Uri, sed, rw)
}

func (cc *CloudConsole) Start(ctx context.Context, rw ReadWriterWithTermInfo) error {
	// do the preflight check
	_, _, err := rw.ScreenSize()
	if err != nil {
		return fmt.Errorf("failed to retrieve screen size: %w", err)
	}
	ccs, err := cc.getCloudConsoleSettings(ctx)
	if err != nil {
		return err
	}
	if ccs.NetworkType == "Isolated" {
		return cc.startIsolated(ctx, ccs, rw)
	} else {
		return cc.startPublic(ctx, ccs, rw)
	}
}

func NewCloudConsole(baseUrl string, tx *http.Transport, tokenFetcher TokenFetcher, nowGetter func() time.Time) (*CloudConsole, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &CloudConsole{
		baseUrl: strings.TrimRight(baseUrl, "/"),
		hc: &http.Client{
			Transport: tx,
			Jar:       jar,
		},
		wsDialer: &websocket.Dialer{
			Jar: jar,
		},
		tokenFetcher: tokenFetcher,
		nowGetter:    nowGetter,
	}, nil
}
