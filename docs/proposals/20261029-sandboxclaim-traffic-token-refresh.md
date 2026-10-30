# SandboxClaim traffic access token refresh

## Contract

Reuse `POST /kruise/api/sandboxes/{sandboxID}/traffic-access-token` and its
existing response fields. The API-key branch is unchanged. A bearer-only
request must supply exactly one `namespace` query parameter and is authenticated
with one Kubernetes TokenReview using the manager's credentials. Only canonical
ServiceAccount usernames with a nonempty UID are accepted. Mixed credentials,
invalid bearer credentials and unavailable TokenReview fail closed. Other E2B
routes do not gain Kubernetes authentication.

The API layer owns TokenReview and HTTP status mapping. Manager receives a
protocol-neutral authenticated identity and owns authorization. Infra retains
cached Sandbox lookup and provider issuance. No caller SubjectAccessReview or
APIReader GET/List is introduced.

## Trusted delivery binding

Claim CREATE admission records the requesting ServiceAccount username and UID
in metadata annotations:

* `agents.kruise.io/traffic-token-service-account-username`
* `agents.kruise.io/traffic-token-service-account-uid`

The pair is immutable on Claim UPDATE. Non-ServiceAccount creators retain the
existing Claim workflow, without a refresh binding. User-supplied copies of
these keys in `spec.annotations` are rejected. A final-state validator checks
the identity derived from AdmissionReview, not merely the presence of a patch.

The Claim controller copies only these trusted metadata annotations into the
delivered Sandbox and keeps `agents.kruise.io/owner` equal to the Claim UID.
Sandbox admission protects the entire owner/username/UID tuple: only the
configured controller ServiceAccount may establish or change a binding, and
partial bindings are rejected. Webhooks fail closed and cover CREATE/UPDATE,
including Kubernetes PATCH requests. Administrators able to disable admission
or impersonate the controller remain trusted.

Missing bindings are not backfilled. Existing or directly created Sandboxes
must be recreated through authenticated Claim admission, or migrated by a
separately authorized administrator. Claim TTL deletion does not remove the
Sandbox binding; refresh never needs to read the Claim.

## Authorization and concurrency

Resolve the explicit namespace and unmodified public Sandbox ID through the
existing cache. Require a nonempty owner, matching bound username and UID,
Running/Paused state, and JWT-enabled route. Check authorization before joining
an issuance flight. Separate flights by the authorization snapshot, including
namespace, public ID, object UID, owner and authenticated identity. At the
provider boundary recheck that snapshot; a recreated Sandbox cannot inherit
an in-flight result.

Bearer authentication failure is 401; missing target or mismatched binding is
uniformly 404; incompatible lifecycle/JWT configuration is 409; TokenReview or
provider unavailability is 503. Preserve API-key status behavior. Neither
bearer credentials nor issued JWTs are persisted in Claim/Sandbox resources.

Cached reads have the same informer observation window as existing manager
operations. This feature does not promise instantaneous revocation. Revoking
the caller's Sandbox RBAC does not revoke refresh authorization; deleting its
ServiceAccount or changing the protected binding affects subsequent reviews
and cache observations. Already issued JWTs remain valid until expiration.

The sandbox-manager runtime does not recycle Sandbox CRs. The independent
controller's existing recycle implementation must not retain a previous
delivery's ServiceAccount annotations. This proposal does not add recycle
handling to manager, Infra, quota or token flows.

## Go client

Keep signing HTTP traffic separate from gateway traffic. Read renewable bearer
credentials for every actual refresh, require a trusted HTTPS manager endpoint,
and never redirect bearer credentials. Cache the JWT separately for each runtime
client/instance, refresh before server-reported expiration, merge concurrent
refreshes, and refuse to send expired credentials after a failed refresh.
Inject `e2b-traffic-access-token` without a Bearer prefix for every request and
stream establishment. Preserve the independent runtime `X-Access-Token`.

The local `agents-api` checkout is read-only and this agents checkout does not
contain its handwritten runtime source. Any runtime changes must be delivered
from an explicitly owned source location, not by editing that synced checkout.
The SDK transport implemented here is independently usable with HTTP clients;
upstream runtime option integration requires resolving that source ownership.

## Deployment and isolation

Install fail-closed Claim/Sandbox admission before enabling bearer refresh.
The controller identity must match the deployed ServiceAccount. Grant only
`create` on `authentication.k8s.io/tokenreviews` to sandbox-manager; business
ServiceAccounts need no TokenReview or SAR permission.

This endpoint does not isolate Kubernetes CRUD or hide runtime access tokens
from namespace-wide Sandbox readers. Use per-tenant namespaces or a separately
designed discovery/credential-delivery policy for complete tenant isolation.
Use a real JWT identity provider and an explicitly short traffic-token validity;
the community placeholder provider is not a JWT issuer.
