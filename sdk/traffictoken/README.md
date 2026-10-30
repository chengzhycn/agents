# SandboxClaim traffic token client

`traffictoken` is a standard-library Go client for refreshing a SandboxClaim
traffic JWT and injecting it into data-plane HTTP requests. Each `Client` owns
one Sandbox instance's cache. There is no package-global token cache.

## Usage

Create a dedicated HTTPS client for sandbox-manager and a separate transport
for runtime traffic. The bearer provider is called for every actual refresh,
so it can read a projected ServiceAccount token or another renewable API token.

```go
import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/openkruise/agents/sdk/traffictoken"
)

roots, err := x509.SystemCertPool()
if err != nil {
	return err
}

signingClient := &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}},
}

tokens, err := traffictoken.New(traffictoken.Config{
	ManagerURL:          "https://sandbox-manager.example.test",
	Namespace:           "tenant-a",
	SandboxID:           sandboxID,
	SandboxUID:          sandboxUID,
	BearerTokenProvider: traffictoken.BearerTokenFile("/var/run/secrets/kubernetes.io/serviceaccount/token"),
	SigningClient:       signingClient,
})
if err != nil {
	return err
}

runtimeTransport, err := tokens.NewTransport(
	"https://49999-sandbox.example.test",
	http.DefaultTransport,
)
if err != nil {
	return err
}
runtimeClient := &http.Client{Transport: runtimeTransport}
```

A callback can provide an API token from any renewable source:

```go
BearerTokenProvider: func(ctx context.Context) (string, error) {
	return tokenStore.Current(ctx)
},
```

Call `tokens.Refresh(ctx)` to force an explicit refresh. Overlapping explicit
and demand-driven refreshes are coalesced. A failed near-expiry refresh may use
the still-valid cached token; after expiration, the transport returns
`ErrTokenExpired` without sending the runtime request.

## Security and transport binding

- `ManagerURL` must be HTTPS and cannot contain userinfo, a query, or a fragment.
- Signing requests never follow redirects. The signing bearer is used only on
  the dedicated manager request and is never added to runtime requests.
- `NewTransport` requires an exact allowed origin. Cross-origin redirects fail
  with `ErrOriginMismatch` before the traffic JWT can be sent to another host.
- Runtime requests are cloned before `e2b-traffic-access-token` is set. Existing
  headers, including the independent `X-Access-Token`, remain unchanged.
- Use a new `Client` when the Sandbox UID changes. `SandboxUID` binds the
  instance-local cache to the delivered Sandbox identity.

This package is independently usable with `net/http`. This repository does not
contain the owned handwritten source for `runtime.NewFromK8s`, so integrating
these options into that upstream runtime requires resolving source ownership;
this package does not claim to modify that runtime.
