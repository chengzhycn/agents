---
title: E2B Enhanced Egress Network Policy
authors:
  - "@chengzhycn"
creation-date: 2026-08-05
last-updated: 2026-08-05
status: implementable
see-also:
  - "/docs/proposals/20260521-traffic-policy-and-security-profile.md"
---

# E2B Enhanced Egress Network Policy

## Summary

Align the E2B-compatible network API with E2B replacement semantics while using
`agents.kruise.io` traffic policies efficiently. `allow_internet_access` binds a
sandbox to a shared deny-internet `GlobalTrafficPolicy`; `allowOut` and
`denyOut` compile independently into at most one per-sandbox `TrafficPolicy`.

## Motivation

The initial implementation compiled any local policy as implicit default-deny,
ignored `allow_internet_access` during PUT, used priority 1000 for local rules,
and allowed 100 API entries even though one CR rule accepts only 20 peers. It
also reconstructed API state from generated rules, which cannot distinguish a
user rule from a synthetic compiler rule.

### Goals

- Preserve default-open E2B behavior and allow-before-deny precedence.
- Make PUT a complete replacement including `allow_internet_access`.
- Keep the shared GTP path for sandboxes with internet disabled and no content rules.
- Follow `API -> Manager -> Infra` layering.
- Persist desired state separately from generated rules.
- Reject the 21st item in either list at the API boundary.

### Non-Goals

- UDP or ICMP enforcement.
- Wildcard FQDN support.
- Waiting for data-plane `Programmed` status.
- Creating the shared GTP from sandbox-manager; the addon owns that resource.

## Proposal

### Desired State

Sandbox annotations persist the effective state and its SHA-256 hash:

```json
{
  "allowInternetAccess": true,
  "allowOut": ["api.example.com"],
  "denyOut": ["10.0.0.0/8"]
}
```

GET reads this annotation. Sandboxes created before this annotation existed use
the internet-access label and TrafficPolicy as a best-effort legacy fallback.
An expiring, unique operation annotation serializes updates across manager
replicas. Lease changes use APIReader-fresh resource-version CAS rather than the
informer cache, and each operation has a deadline shorter than its lease. The
desired hash identifies state; it is not used as a transaction ID.

### Policy Layers

The addon supplies one cluster-scoped policy:

```yaml
priority: 900
selector:
  matchLabels:
    agents.kruise.io/allow-internet-access: "false"
egress:
  rules:
  - action: reject
    to:
    - cidr: 0.0.0.0/0
```

Sandbox-manager uses priority 100 for local policies. Smaller priorities are
evaluated first in the enhanced data plane, so explicit local allows terminate
before the global fallback rejects unmatched traffic.

| Internet | allowOut | denyOut | Local policy |
|---|---|---|---|
| true | empty | empty | none |
| true | set | empty | allow, allow-all |
| true | empty | narrow | reject, allow-all |
| true | set | narrow | allow, reject, allow-all |
| true | any | `0.0.0.0/0` | optional allow, reject-all |
| false | empty | empty | none; GTP rejects |
| false | set | any | allow then optional reject; GTP fallback |

The original internet flag alone sets the label. A deny-all content rule never
changes GTP selection.

### Layering and Failure Handling

The E2B API validates protocol fields, applies default `true`, deduplicates
entries, and invokes Manager. Manager owns create, clone, update, read, rollback,
and recycle orchestration. The Kubernetes Infra implementation checks the GTP
capability, reconciles the local TP, then writes label and desired annotations.

Create or clone network failure deletes the claimed sandbox and releases its
quota admission even when failed-sandbox debug retention was requested. Network
policy setup runs after claim/create persistence but before readiness waits and
runtime initialization. Recycle clears and verifies local network state while
holding the same operation lease, then atomically marks the Sandbox for cleanup.
Kubernetes deletion failures are returned rather than logged as success.
Repeating the same desired state does not create duplicate policies.

Transitions use restrictive staging policies. Disabling internet with no local
rules first installs local reject-all, binds the GTP, revalidates the GTP, and
then removes staging. Enabling internet with local rules installs the rules
without an allow-all tail, switches the label, and only then adds the final
allow-all tail. Failures therefore over-deny rather than temporarily open egress.

## Upgrade Strategy

1. Install the priority 900 GTP before accepting disabled-internet requests.
2. Deploy sandbox-manager with priority 100 local compilation.
3. Existing policies are rewritten on their next PUT; a migration job may
   backfill desired annotations for untouched sandboxes.
4. Keep the legacy read fallback until the backfill is complete.

## Test Plan

- Table-drive the complete internet/allow/deny truth table.
- Verify priority 100 and stable rule ordering.
- Verify 20 succeeds and 21 returns HTTP 400.
- Verify false fails with HTTP 503 when the expected GTP is absent.
- Verify PUT updates sandbox and pod-template labels.
- Verify GET returns raw desired entries and hides synthetic allow-all.
- Verify create failure rollback and recycle cleanup.

The enhanced implementation controls TCP only; validation and product
documentation must continue to state that UDP and ICMP are outside this policy.
