package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/azure/cli"
	"github.com/moriyoshi/az-cloud-shell-access/internal/oauth2"
	"github.com/shibukawa/configdir"
	"github.com/spf13/cobra"
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

func consoleDo(tenantId, clientId string, callback func(context.Context, *CloudConsole) error) (string, int) {
	tx := &http.Transport{
		MaxIdleConns:    2,
		IdleConnTimeout: 10 * time.Second,
	}
	authority := fmt.Sprintf("%s%s", authEndpointPrefix, url.PathEscape(tenantId))
	cd := configdir.New("", "az-cloud-shell-access")
	var credsPath string
	{
		c := cd.QueryFolders(configdir.Cache)[0]
		err := os.MkdirAll(c.Path, 0700)
		if err != nil {
			return "failed to create cache directory", 1
		}
		credsPath = filepath.Join(c.Path, "accessTokens.json")
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
		return err.Error(), 1
	}
	_, err = c.FetchTokens(ctx, false)
	if err != nil {
		return err.Error(), 1
	}

	console, err := NewCloudConsole(
		"https://management.azure.com/",
		tx,
		func() (*oauth2.Tokens, error) {
			return c.FetchTokens(ctx, true)
		},
		time.Now,
		message,
	)
	if err != nil {
		return err.Error(), 1
	}

	err = callback(ctx, console)
	if err != nil {
		return err.Error(), 2
	}
	return "", 0
}

var tenantId string
var clientId string

func checkTenantIdAndClientId() {
	if clientId == "" {
		clientId = defaultClientId
	}
	if clientId == "" {
		message("no default client ID is provided, and AZURE_CLIENT_ID environment variable is not set.")
		os.Exit(1)
	}
	if tenantId == "" {
		message("no default subscription found in Azure CLI profile, and AZURE_TENANT_ID environment variable is not set.")
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use: progName,
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&tenantId, "tenant-id", "", "Azure Tenant ID")
	rootCmd.PersistentFlags().StringVar(&clientId, "client-id", "", "Azure Client ID")
	{
		var envVars []string
		shellCmd := &cobra.Command{
			Use:   "shell",
			Short: "start interative shell",
			Run: func(cmd *cobra.Command, args []string) {
				checkTenantIdAndClientId()
				envVarsMap := make(map[string]string)
				for _, envVar := range envVars {
					pair := strings.SplitN(envVar, "=", 2)
					k := pair[0]
					v := ""
					if len(pair) > 1 {
						v = pair[1]
					}
					envVarsMap[k] = v
				}
				msg, status := consoleDo(tenantId, clientId, func(ctx context.Context, console *CloudConsole) error {
					defer message("connection closed")
					return console.Start(ctx, &TerminalReadWriter{os.Stdin}, envVarsMap)
				})
				if msg != "" {
					message(msg)
				}
				os.Exit(status)
			},
		}
		shellCmd.Flags().StringSliceVarP(&envVars, "env", "e", nil, "environment variable in NAME=VALUE format")
		rootCmd.AddCommand(shellCmd)
	}
	{
		var port int
		var localAddr string
		proxyCmd := &cobra.Command{
			Use:   "proxy",
			Short: "start HTTP proxy",
			Run: func(cmd *cobra.Command, args []string) {
				if localAddr == "" {
					localAddr = fmt.Sprintf("[::1]:%d", port)
				}
				checkTenantIdAndClientId()
				msg, status := consoleDo(tenantId, clientId, func(ctx context.Context, console *CloudConsole) error {
					return console.Proxy(
						ctx, port, localAddr,
						func(ctx context.Context, port int, localAddr string) error {
							message(fmt.Sprintf("proxying port %d => %s", port, localAddr))
							return nil
						},
						func(_ int, _ string) {
							message("proxy port closed")
						},
					)
				})
				if msg != "" {
					message(msg)
				}
				os.Exit(status)
			},
		}
		proxyCmd.Flags().IntVar(&port, "port", 8091, "port to proxy")
		proxyCmd.Flags().StringVar(&localAddr, "local-addr", "", "local address")
		rootCmd.AddCommand(proxyCmd)
	}
}

func initConfig() {
	tenantId = os.Getenv("AZURE_TENANT_ID")
	clientId = os.Getenv("AZURE_CLIENT_ID")
	if tenantId == "" {
		tenantId, _ = determineTernantWithAzCliProfile()
	}
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		message(err.Error())
		os.Exit(1)
	}
}
