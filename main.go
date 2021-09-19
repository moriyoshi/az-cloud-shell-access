package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/go-autorest/autorest/azure/cli"
	"github.com/moriyoshi/az-cloud-shell-access/internal/oauth2"
	"github.com/shibukawa/configdir"
)

var progName = filepath.Base(os.Args[0])

func message(msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", progName, msg)
}

type ErrNoDefaultSubscriptionFound struct{}

func (*ErrNoDefaultSubscriptionFound) Error() string {
	return "no default subscription found"
}

func determineTernantWithAzCliProfile() (string, error) {
	path, err := cli.ProfilePath()
	if err != nil {
		return "", err
	}
	p, err := cli.LoadProfile(path)
	if err != nil {
		return "", err
	}
	for _, s := range p.Subscriptions {
		if s.IsDefault {
			return s.TenantID, nil
		}
	}
	return "", &ErrNoDefaultSubscriptionFound{}
}

const authEndpointPrefix = "https://login.microsoftonline.com/"

var defaultClientId string

func main() {
	tenantId := os.Getenv("AZURE_TENANT_ID")
	clientId := os.Getenv("AZURE_CLIENT_ID")
	var err error
	if tenantId == "" {
		tenantId, err = determineTernantWithAzCliProfile()
		if err != nil {
			message("no default subscription found in Azure CLI profile, and AZURE_TENANT_ID environment variable is not set.")
			os.Exit(255)
		}
	}
	tx := &http.Transport{
		MaxIdleConns:    2,
		IdleConnTimeout: 10 * time.Second,
	}
	authority := fmt.Sprintf("%s%s", authEndpointPrefix, url.PathEscape(tenantId))
	cd := configdir.New("", "az-cloud-shell-access")
	var credsPath string
	{
		c := cd.QueryFolders(configdir.Cache)[0]
		err = os.MkdirAll(c.Path, 0700)
		if err != nil {
			message("failed to create cache directory")
			os.Exit(1)
		}
		credsPath = filepath.Join(c.Path, "accessTokens.json")
	}
	if clientId == "" {
		clientId = defaultClientId
	}
	ctx := context.Background()
	c, err := oauth2.NewClient(
		tx, clientId,
		oauth2.WithConfigurationOverrides(
			oauth2.OpenIDConfiguration{
				TokenEndpoint:               authEndpointPrefix + "common/oauth2/token",
				DeviceAuthorizationEndpoint: authEndpointPrefix + "common/oauth2/devicecode",
			},
		),
		oauth2.WithResource("https://management.core.windows.net/"),
		oauth2.WithFlow(
			oauth2.NewLegacyDeviceCodeFlow(
				func(msg string) error {
					fmt.Println(msg)
					return nil
				},
			),
		),
		oauth2.WithNowGetter(time.Now),
		oauth2.WithTokenStore(
			oauth2.NewSimpleTokenStore(credsPath, authority, time.Now),
		),
	)
	if err != nil {
		message(err.Error())
		os.Exit(1)
	}
	_, err = c.FetchTokens(ctx, false)
	if err != nil {
		message(err.Error())
		os.Exit(1)
	}

	console, err := NewCloudConsole(
		"https://management.azure.com/",
		tx,
		func() (*oauth2.Tokens, error) {
			return c.FetchTokens(ctx, true)
		},
		time.Now,
	)
	if err != nil {
		message(err.Error())
		os.Exit(1)
	}

	err = console.Start(ctx, &TerminalReadWriter{os.Stdin})
	if err != nil {
		message(err.Error())
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "connection closed.\n")
}
