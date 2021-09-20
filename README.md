# az-cloud-shell-access

## What is this?

This is a tiny program that allows one to connect to Azure Cloud Shell
from within the ordinary Unix terminal, not from the web browser.

## Usage

You need to get your resource group and storage account ready by opening up Cloud Shell at Azure Portal at least once.

https://shell.azure.com/

If you've already set up azure CLI, then just type

```
$ ./az-cloud-shell-access shell
```

to connect to the cloud shell instance that resides within the tenant of the default subscription.

If you want to use the instance in the different tenant, specify `AZURE_TENANT_ID` environment variable.

### HTTP forwarding

Azure Cloud Shell has built-in HTTP forward proxy support.

```
$ ./az-cloud-shell-access proxy --port 8092 --local-addr :8080
```

will instruct Azure Cloud Shell control plane and az-cloud-shell-access to forward HTTP requests to the local address `:8080` to the remote address `127.0.0.1:8092`.

The remote port must be in range of 1025-8079 and 8091-49151.

## The protocol

Details are taken from windows Terminal's Azure Cloud Shell connector.

https://github.com/microsoft/terminal/blob/main/src/cascadia/TerminalConnection/AzureConnection.cpp
