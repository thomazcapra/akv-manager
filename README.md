# akv-manager

A local web console to browse and manage **Azure Key Vaults** — secrets, keys,
certificates, and expiry — across every subscription you can see.

**No credentials are stored or bundled.** It calls `az` once to mint a short-lived
token (reusing your existing `az login`, so it respects MFA / conditional access) and
then talks to Azure's REST APIs directly. Every user runs it as **their own** Azure
identity, with exactly the permissions their `az login` grants. The server binds to
`127.0.0.1` only — it is never exposed to the network.

## Run it

```bash
npx akv-manager
```

That's it — it starts a local server, opens your browser, and uses whatever account
you're logged into with `az`. Prerequisites:

- **Node.js ≥ 18**
- **Azure CLI** (`az`) installed and signed in (`az login`)

If you're not signed in, the UI tells you to run `az login` and press Refresh.

## What you can do

- **Overview** — accounts, subscriptions, and vault counts per environment.
- **Subscriptions** — switch the active subscription.
- **Key Vaults** — live Resource Graph sweep across every subscription you can read;
  filter, sort, see RBAC-vs-policy auth and SKU. Open a vault to inspect/edit its
  **secrets, keys and certificates**.
  - reveal a secret value, **create** secrets (one or in batch with a common expiry),
    **edit** values (current value pre-filled), and **batch** enable/disable/set-expiry.
- **Expiry** — scan every readable vault for secrets/certs that are expired or near
  expiry, plotted on a time horizon.
- **Clusters** — read-only AKS monitoring: browse namespaces and pods, read **pod
  logs** and **configmaps**, all as your own `az` identity. Talks to the Kubernetes
  API directly (no `kubectl`/`kubelogin` needed) via an AAD token for the managed
  AAD server app. Private API servers need you on the right network (e.g. corporate
  VPN); the UI flags it when a cluster is unreachable.

### Configuring AKS clusters

Clusters you have ARM *Reader* on are auto-discovered. If you only have **data-plane**
(Kubernetes-RBAC) access — common — list them yourself via either variable:

```bash
# inline JSON …
AZBO_AKS_CLUSTERS='[{"name":"my-aks","resourceGroup":"my-rg","subscription":"My Sub","env":"Dev","label":"My cluster"}]' npx akv-manager

# … or a file
AZBO_AKS_CLUSTERS_FILE=./aks-clusters.json npx akv-manager
```

Each entry needs `name`, `resourceGroup`, `subscription` (name or id); `env` and
`label` are optional. The console never bundles any cluster list — it's yours to provide.

## Configuration (all optional, via environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `4173` | Port to listen on (auto-increments if busy). |
| `HOST` | `127.0.0.1` | Bind address. Keep it local. |
| `AZBO_NO_OPEN` | — | Set to anything to skip auto-opening the browser. |
| `AZBO_TITLE` | `Keyvault Console` | Custom title shown in the sidebar. |
| `AZBO_ENV_RULES` | — | JSON `[["pattern","Label"], …]` mapping subscription-name patterns to environment labels. |
| `AZBO_PROTECTED_TAGS` | governance set | Comma-separated tag names that are read-only in the UI (`*` = prefix wildcard). Set empty to disable. |
| `AZBO_AKS_CLUSTERS` | — | JSON array of `{name,resourceGroup,subscription,env?,label?}` clusters to monitor. |
| `AZBO_AKS_CLUSTERS_FILE` | — | Path to a JSON file with the same cluster array. |
| `AZ_PATH` | `az` | Path to the Azure CLI binary. |
| `AZ_TIMEOUT` | `120000` | Per-`az`-call timeout (ms). |

By default environments are inferred from common keywords (`dev`, `test`, `qa`,
`stage`, `uat`, `prod`, `sandbox`). If your subscription names use a different
convention, map them yourself, e.g.:

```bash
AZBO_ENV_RULES='[["-prd-","Prod"],["-dev-","Dev"],["-tst-","Test"]]' npx akv-manager
```

## Notes on access

- Seeing a vault in the list is **management-plane** visibility. Reading its secrets
  is a separate **data-plane** permission — the UI shows 🔒 when you lack it.
- Some vaults restrict access by **IP firewall**. If you're off the corporate VPN you
  may be blocked at the network layer — the UI flags this as 🚫 *firewall / VPN*, not a
  permission problem.
- Write actions (create/edit/enable/disable) only succeed where you have write
  permission; failures are reported per item.

## Publishing (for maintainers)

```bash
npm publish        # name must be available on the registry you publish to
```

Until then you can run it straight from a tarball or git:

```bash
npm pack                     # produces akv-manager-x.y.z.tgz
npx ./akv-manager-1.0.0.tgz  # or: npx <git-url>
```

## License

[MIT](./LICENSE) © Thomaz Capra
