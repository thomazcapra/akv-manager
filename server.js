#!/usr/bin/env node
'use strict';

/**
 * akv-manager — a small local Express server that uses your Azure CLI login
 * to manage accounts, subscriptions and Key Vaults.
 *
 * It runs every command as the currently logged-in `az` user, so it has exactly
 * the permissions that `az login` granted — nothing more. Bound to 127.0.0.1 by
 * default so it is not reachable from the network.
 */

const express = require('express');
const { execFile } = require('child_process');
const path = require('path');

const AZ = process.env.AZ_PATH || 'az';
const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || '127.0.0.1';
// az can be slow on the first call of a session (token refresh, extension load).
const AZ_TIMEOUT = Number(process.env.AZ_TIMEOUT || 120000);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- helpers ---------------------------------------------------------------

const NAME_RE = /^[A-Za-z0-9-]{1,127}$/;            // vault / secret / key names
const SUB_RE = /^[0-9a-fA-F-]{1,40}$|^[\w .()-]{1,80}$/; // sub id or display name

function isValidName(v) { return typeof v === 'string' && NAME_RE.test(v); }

/** Run az with an args array. Returns parsed JSON.
 *  az() only runs trusted, fixed commands (get-access-token / logout) — never user
 *  input — so enabling the shell on Windows (required to launch az.cmd) is safe here. */
function az(args, { json = true } = {}) {
  const finalArgs = json ? [...args, '--output', 'json'] : args;
  const isWin = process.platform === 'win32';
  return new Promise((resolve, reject) => {
    execFile(AZ, finalArgs, {
      timeout: AZ_TIMEOUT, maxBuffer: 64 * 1024 * 1024,
      shell: isWin,          // on Windows the CLI is `az.cmd`; execFile can't run it without a shell
      windowsHide: true,
    }, (err, stdout, stderr) => {
        if (err) {
          const msg = (stderr || err.message || '').trim();
          const notFound = err.code === 'ENOENT' || /not recognized|cannot find the (path|file)|ENOENT/i.test(msg);
          return reject(Object.assign(new Error(
            notFound ? `Azure CLI not found (tried "${AZ}"). Install the Azure CLI, or set AZ_PATH to its full path.` : (msg || 'az command failed')), {
            azError: true, notFound,
            needLogin: /AADSTS70043|refresh token|please run ['"]?az login|InvalidAuthenticationToken|expired|no subscription|not logged in/i.test(msg),
            forbidden: /Forbidden|does not have secrets|AccessDenied|not authorized|403/i.test(msg),
            stderr: msg, args: finalArgs,
          }));
        }
        if (!json) return resolve(stdout);
        try { resolve(stdout.trim() ? JSON.parse(stdout) : null); }
        catch (e) { reject(new Error('Failed to parse az output: ' + e.message)); }
      });
  });
}

function send(res, p) {
  p.then((data) => res.json({ ok: true, data }))
   .catch((err) => res.status(err.status || (err.needLogin ? 401 : err.forbidden ? 403 : err.notFound ? 404 : 500)).json({
     ok: false, error: err.stderr || err.message,
     needLogin: !!err.needLogin, forbidden: !!err.forbidden, firewall: !!err.firewall,
     network: !!err.network, notFound: !!err.notFound,
   }));
}

// ---- simple in-memory cache for the expensive vault sweep ------------------

let vaultCache = { at: 0, data: null };
const VAULT_TTL = 60 * 1000;

// ---- Key Vault data plane over REST (fast path) ----------------------------
// Spawning `az` per lookup costs ~1-2s of Python startup each. Instead we grab a
// data-plane token once (via az), cache it, and call the vault's REST API directly
// with fetch — turning each lookup into a ~100-300ms HTTP request.

const KV_API = '7.4';
const VAULT_RES = 'https://vault.azure.net';
const ARM_RES = 'https://management.azure.com';

// One token per resource (ARM vs Key Vault have different audiences), cached.
// `az account get-access-token` is the ONLY remaining az call on the hot path —
// it bridges the existing az login (MFA / conditional access) into a bearer token;
// everything else below is plain fetch against Azure REST.
const tokenCache = new Map(); // resource -> { token, exp, pending }

async function getToken(resource) {
  const c = tokenCache.get(resource);
  if (c && c.token && Date.now() < c.exp) return c.token;
  if (c && c.pending) return c.pending;
  const pending = (async () => {
    const out = await az(['account', 'get-access-token', '--resource', resource]);
    tokenCache.set(resource, { token: out.accessToken, exp: Date.now() + 45 * 60 * 1000, pending: null });
    return out.accessToken;
  })();
  tokenCache.set(resource, { ...(c || {}), pending });
  try { return await pending; }
  catch (e) { tokenCache.delete(resource); throw e; }
}
const getVaultToken = () => getToken(VAULT_RES);
const getArmToken = () => getToken(ARM_RES);

function decodeJwt(t) {
  try {
    const p = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(p, 'base64').toString('utf8'));
  } catch { return {}; }
}

// Azure Resource Manager REST call (management plane).
async function armFetch(pathOrUrl, { method = 'GET', body, timeout = 40000 } = {}) {
  const token = await getArmToken();
  const url = pathOrUrl.startsWith('http') ? pathOrUrl : `${ARM_RES}${pathOrUrl}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  let resp;
  try {
    resp = await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
  } catch (e) {
    throw Object.assign(new Error(e.name === 'AbortError' ? 'ARM request timed out' : e.message), { timedOut: e.name === 'AbortError' });
  } finally { clearTimeout(timer); }
  if (resp.status === 401) { tokenCache.delete(ARM_RES); throw Object.assign(new Error('Token rejected — run az login'), { needLogin: true }); }
  if (resp.status === 403) throw Object.assign(new Error('Forbidden'), { forbidden: true });
  if (!resp.ok) throw new Error(`ARM ${resp.status}: ${(await resp.text()).slice(0, 200)}`);
  return resp.json();
}

let subsCache = { at: 0, data: null };
const SUBS_TTL = 60 * 1000;
async function listSubscriptions(force) {
  if (!force && subsCache.data && Date.now() - subsCache.at < SUBS_TTL) return subsCache.data;
  const out = await armFetch('/subscriptions?api-version=2022-12-01');
  const data = out.value || [];
  subsCache = { at: Date.now(), data };
  return data;
}
let selectedSub = null; // active subscription (server-side context, replaces `az account set`)

// Tell apart a real permission denial from a Key Vault firewall / network block.
async function forbiddenError(resp) {
  let msg = 'Forbidden';
  try { const j = await resp.json(); msg = (j.error && j.error.message) || msg; } catch { /* ignore */ }
  const firewall = /Client address is not authorized|public network access is disabled|not allowed to access|trusted service/i.test(msg);
  return Object.assign(new Error(msg), { forbidden: true, firewall });
}

async function kvFetch(name, pathQuery, { timeout = 15000 } = {}) {
  const token = await getVaultToken();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  let resp;
  try {
    resp = await fetch(`https://${name.toLowerCase()}.vault.azure.net${pathQuery}`,
      { headers: { Authorization: `Bearer ${token}` }, signal: ctrl.signal });
  } catch (e) {
    throw Object.assign(new Error(e.name === 'AbortError' ? 'Vault request timed out' : e.message), { timedOut: e.name === 'AbortError' });
  } finally { clearTimeout(timer); }
  if (resp.status === 401) { tokenCache.delete(VAULT_RES);
    throw Object.assign(new Error('Token rejected — run az login'), { needLogin: true }); }
  if (resp.status === 403) throw await forbiddenError(resp);
  if (resp.status === 404) throw Object.assign(new Error('Vault or item not found'), { notFound: true });
  if (resp.status === 429) throw Object.assign(new Error('Throttled'), { throttled: true });
  if (!resp.ok) throw new Error(`Key Vault returned ${resp.status}`);
  return resp.json();
}

// Normalize a REST item to the shape the frontend/scan expect (az-like).
function normItem(it) {
  const a = it.attributes || {};
  return {
    id: it.id,
    name: (it.id || '').split('/').pop(),
    managed: it.managed === true,
    contentType: it.contentType,
    attributes: {
      enabled: a.enabled !== false,
      expires: a.exp ? new Date(a.exp * 1000).toISOString() : null,
    },
  };
}

// List all items of a kind ('secrets'|'keys'|'certificates'), following paging.
async function kvList(name, kind, { maxPages = 400, timeout } = {}) {
  let pathQuery = `/${kind}?api-version=${KV_API}&maxresults=25`;
  const items = [];
  for (let p = 0; p < maxPages; p++) {
    const data = await kvFetch(name, pathQuery, { timeout });
    for (const it of (data.value || [])) items.push(normItem(it));
    if (!data.nextLink) break;
    const u = new URL(data.nextLink);
    pathQuery = u.pathname + u.search;
  }
  return items;
}

// Short cache for list results so reopening a vault is instant.
const listCache = new Map(); // `${name}/${kind}` -> { at, data }
const LIST_TTL = 30 * 1000;
async function kvListCached(name, kind) {
  const key = `${name}/${kind}`;
  const hit = listCache.get(key);
  if (hit && Date.now() - hit.at < LIST_TTL) return hit.data;
  const data = await kvList(name, kind);
  listCache.set(key, { at: Date.now(), data });
  return data;
}

// ---- API: accounts & subscriptions ----------------------------------------

app.get('/api/account', (req, res) =>
  send(res, (async () => {
    const claims = decodeJwt(await getArmToken());
    const subs = await listSubscriptions();
    if (!selectedSub && subs.length) selectedSub = subs[0].subscriptionId;
    const cur = subs.find((s) => s.subscriptionId === selectedSub) || subs[0] || {};
    return {
      user: { name: claims.upn || claims.unique_name || claims.name || claims.email || 'signed in' },
      name: cur.displayName || '', id: cur.subscriptionId || '',
      tenantId: claims.tid || cur.tenantId || '',
    };
  })()));

app.get('/api/subscriptions', (req, res) =>
  send(res, (async () => {
    const subs = await listSubscriptions(!!req.query.refresh);
    if (!selectedSub && subs.length) selectedSub = subs[0].subscriptionId;
    return subs.map((s) => ({
      id: s.subscriptionId, name: s.displayName, state: s.state,
      tenantId: s.tenantId, isDefault: s.subscriptionId === selectedSub,
    }));
  })()));

app.post('/api/subscription/set', (req, res) => {
  const { subscription } = req.body || {};
  if (!subscription || !SUB_RE.test(subscription))
    return res.status(400).json({ ok: false, error: 'Invalid subscription id/name' });
  // With everything on REST, the "active subscription" is just server state.
  send(res, (async () => {
    const subs = await listSubscriptions();
    const cur = subs.find((s) => s.subscriptionId === subscription);
    if (!cur) throw new Error('Subscription not found');
    selectedSub = subscription;
    const claims = decodeJwt(await getArmToken());
    return { user: { name: claims.upn || claims.unique_name || claims.name || 'signed in' },
      name: cur.displayName, id: cur.subscriptionId, tenantId: claims.tid || cur.tenantId };
  })());
});

app.post('/api/logout', (req, res) => {
  tokenCache.clear(); subsCache = { at: 0, data: null }; vaultCache = { at: 0, data: null };
  send(res, az(['logout'], { json: false }).then(() => ({ loggedOut: true })).catch(() => ({ loggedOut: true })));
});

// ---- API: Key Vault inventory (Resource Graph across all subscriptions) ----

const VAULT_QUERY =
  "resources | where type =~ 'microsoft.keyvault/vaults' " +
  "| project name, resourceGroup, subscriptionId, location, " +
  "sku=tostring(properties.sku.name), " +
  "enableRbac=tostring(properties.enableRbacAuthorization), " +
  "uri=tostring(properties.vaultUri), tags " +
  "| order by name asc";

async function listVaultsRaw(force) {
  if (!force && vaultCache.data && Date.now() - vaultCache.at < VAULT_TTL) return vaultCache.data;
  const subIds = (await listSubscriptions(force)).map((s) => s.subscriptionId);
  // Resource Graph returns at most 1000 rows per page; follow $skipToken to get them all.
  const data = [];
  let skipToken;
  for (let page = 0; page < 100; page++) {            // hard stop at 100k vaults — a safety bound
    const options = { resultFormat: 'objectArray', $top: 1000 };
    if (skipToken) options.$skipToken = skipToken;
    const out = await armFetch('/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01', {
      method: 'POST',
      body: { subscriptions: subIds, query: VAULT_QUERY, options },
    });
    if (out.data) data.push(...out.data);
    skipToken = out.$skipToken;
    if (!skipToken) break;
  }
  vaultCache = { at: Date.now(), data };
  return data;
}

app.get('/api/vaults', async (req, res) => {
  try {
    const data = await listVaultsRaw(!!req.query.refresh);
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.needLogin ? 401 : 500)
       .json({ ok: false, error: err.stderr || err.message, needLogin: !!err.needLogin });
  }
});

// Find a vault's management-plane coordinates (sub + rg) from the cached inventory.
async function findVaultMeta(name) {
  const vaults = await listVaultsRaw();
  return vaults.find((v) => (v.name || '').toLowerCase() === name.toLowerCase());
}

// "Default" / governance tags that this tool must never edit or remove — they are
// applied by Azure Policy / automation and are read-only here. Patterns are matched
// case-insensitively; a trailing '*' is a prefix wildcard (e.g. "automation.*").
// Operators can override the whole list with AZBO_PROTECTED_TAGS (comma-separated);
// set it to an empty string to disable protection entirely.
const PROTECTED_TAGS = (() => {
  const def = ['env', 'environment', 'cost-center', 'costcenter', 'contact-*', 'owner',
    'solution', 'location', 'roles', 'managed-by', 'managedby',
    'expirationdate', 'runninginterval', 'automation.*', 'hidden-*'];
  const raw = process.env.AZBO_PROTECTED_TAGS;
  if (raw === undefined) return def;
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
})();
function tagMatch(pattern, key) {
  const p = pattern.toLowerCase(), k = String(key).toLowerCase();
  return p.endsWith('*') ? k.startsWith(p.slice(0, -1)) : k === p;
}
function isProtectedTag(key) { return PROTECTED_TAGS.some((p) => tagMatch(p, key)); }

// Replace a vault's tag set (management plane). The body's `tags` object is the
// COMPLETE desired set — Key Vault's PATCH overwrites the whole tags collection.
// Protected/default tags are force-preserved from the current state, so they can be
// neither edited nor removed regardless of what the client sends.
// Requires management-plane write (e.g. Contributor / Tag Contributor) on the vault.
app.put('/api/vaults/:name/tags', (req, res) => {
  const { name } = req.params;
  if (!isValidName(name)) return res.status(400).json({ ok: false, error: 'Invalid vault name' });
  const { tags } = req.body || {};
  if (!tags || typeof tags !== 'object' || Array.isArray(tags))
    return res.status(400).json({ ok: false, error: 'tags must be an object of name → value' });
  const entries = Object.entries(tags);
  if (entries.length > 50) return res.status(400).json({ ok: false, error: 'Azure allows at most 50 tags per resource' });
  for (const [k, v] of entries) {
    if (typeof k !== 'string' || !k.length || k.length > 512) return res.status(400).json({ ok: false, error: `Invalid tag name: ${k}` });
    if (typeof v !== 'string' || v.length > 256) return res.status(400).json({ ok: false, error: `Invalid value for tag "${k}" (max 256 chars)` });
  }
  send(res, (async () => {
    const v = await findVaultMeta(name);
    if (!v) throw new Error('Vault not found in inventory — try Refresh first');
    const current = v.tags || {};
    // Start from the client's desired set, then force every protected tag that exists
    // today back to its original value — this blocks edit AND removal of default tags.
    const finalTags = {};
    for (const [k, val] of entries) { if (!isProtectedTag(k)) finalTags[k] = val; }
    for (const [k, val] of Object.entries(current)) { if (isProtectedTag(k)) finalTags[k] = val; }
    const url = `/subscriptions/${v.subscriptionId}/resourceGroups/${v.resourceGroup}` +
                `/providers/Microsoft.KeyVault/vaults/${name}?api-version=2023-07-01`;
    const out = await armFetch(url, { method: 'PATCH', body: { tags: finalTags } });
    v.tags = (out && out.tags) || finalTags;     // reflect immediately in the cached inventory
    return { tags: v.tags };
  })());
});

// ---- API: expiring secrets & certificates (scans every readable vault) -----

/** Run async worker over items with bounded concurrency. */
function pool(items, worker, concurrency = 14) {
  return new Promise((resolve) => {
    const out = []; let i = 0, active = 0, finished = 0;
    if (!items.length) return resolve(out);
    const launch = () => {
      while (active < concurrency && i < items.length) {
        const idx = i++; active++;
        Promise.resolve(worker(items[idx], idx))
          .then((r) => { out[idx] = r; })
          .catch(() => { out[idx] = null; })
          .finally(() => {
            active--; finished++;
            if (finished === items.length) resolve(out); else launch();
          });
      }
    };
    launch();
  });
}

function summarizeExpiring(items, days) {
  const now = Date.now();
  const horizon = now + days * 86400000;
  return items
    .map((it) => ({ ...it, daysLeft: Math.floor((Date.parse(it.expires) - now) / 86400000) }))
    .filter((it) => Date.parse(it.expires) <= horizon)   // expired (negative) + expiring soon
    .sort((a, b) => a.daysLeft - b.daysLeft);
}

// Background scan job (scanning hundreds of vaults is too slow for one request).
let scanJob = { running: false, done: 0, total: 0, startedAt: 0, finishedAt: 0,
                items: [], stats: null, error: null };

async function runScan(vaults) {
  const items = [];
  const stats = { total: vaults.length, readable: 0, forbidden: 0, errored: 0 };
  scanJob = { running: true, done: 0, total: vaults.length, startedAt: Date.now(),
              finishedAt: 0, items, stats, error: null };

  const collect = async (vault, kind, type) => {
    try {
      const list = await kvList(vault.name, kind, { maxPages: 400, timeout: 20000 });
      for (const it of list) {
        if (it.managed && type === 'secret') continue;            // skip cert-backing secrets
        const exp = it.attributes && it.attributes.expires;
        if (!exp) continue;
        items.push({
          vault: vault.name, resourceGroup: vault.resourceGroup, subscriptionId: vault.subscriptionId,
          type, name: it.name, expires: exp, enabled: it.attributes.enabled,
        });
      }
      return 'ok';
    } catch (e) { return e.forbidden ? 'forbidden' : 'error'; }
  };

  await pool(vaults, async (v) => {
    // Secrets first; if the vault denies data-plane access, certs will too — skip the call.
    const s = await collect(v, 'secrets', 'secret');
    const c = s === 'forbidden' ? 'forbidden' : await collect(v, 'certificates', 'certificate');
    if (s === 'ok' || c === 'ok') stats.readable++;
    else if (s === 'forbidden') stats.forbidden++;
    else stats.errored++;
    scanJob.done++;
  }, 24);

  scanJob.running = false;
  scanJob.finishedAt = Date.now();
}

app.post('/api/expiring/scan', async (req, res) => {
  if (scanJob.running) return res.json({ ok: true, running: true, done: scanJob.done, total: scanJob.total });
  let vaults;
  try { vaults = await listVaultsRaw(); }
  catch (err) {
    return res.status(err.needLogin ? 401 : 500)
      .json({ ok: false, error: err.stderr || err.message, needLogin: !!err.needLogin });
  }
  runScan(vaults).catch((e) => { scanJob.running = false; scanJob.error = e.message; });
  res.json({ ok: true, running: true, done: 0, total: vaults.length });
});

app.get('/api/expiring/status', (req, res) => {
  const days = Math.min(3650, Math.max(0, Number(req.query.days) || 30));
  res.json({
    ok: true, running: scanJob.running, done: scanJob.done, total: scanJob.total,
    scannedAt: scanJob.finishedAt, stats: scanJob.stats, error: scanJob.error,
    items: scanJob.finishedAt ? summarizeExpiring(scanJob.items, days) : [],
  });
});

// ---- API: per-vault data-plane (secrets / keys / certificates) -------------

for (const kind of ['secrets', 'keys', 'certificates']) {
  app.get(`/api/vaults/:name/${kind}`, (req, res) => {
    const { name } = req.params;
    if (!isValidName(name))
      return res.status(400).json({ ok: false, error: 'Invalid vault name' });
    send(res, kvListCached(name, kind));
  });
}

// Reveal a single secret value (explicit, sensitive action — never cached).
app.get('/api/vaults/:name/secrets/:secret/value', (req, res) => {
  const { name, secret } = req.params;
  if (!isValidName(name) || !isValidName(secret))
    return res.status(400).json({ ok: false, error: 'Invalid name' });
  // REST returns { value, id, attributes, ... } — same `.value` the UI reads.
  send(res, kvFetch(name, `/secrets/${secret}?api-version=${KV_API}`));
});

// ---- API: write operations (update secrets / certificates) -----------------

function invalidateVault(name) {
  for (const k of listCache.keys()) if (k.startsWith(name + '/')) listCache.delete(k);
}

// Build a Key Vault attributes object from { enabled, expires } input.
function buildAttrs(src = {}) {
  const a = {};
  if (typeof src.enabled === 'boolean') a.enabled = src.enabled;
  if (src.expires) {
    const t = Date.parse(src.expires);
    if (!isNaN(t)) a.exp = Math.floor(t / 1000);     // KV wants unix seconds
  }
  return a;
}

async function kvWrite(vaultName, method, pathQuery, body) {
  const token = await getVaultToken();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  let resp;
  try {
    resp = await fetch(`https://${vaultName.toLowerCase()}.vault.azure.net${pathQuery}`, {
      method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: ctrl.signal,
    });
  } catch (e) {
    throw Object.assign(new Error(e.name === 'AbortError' ? 'Vault request timed out' : e.message), {});
  } finally { clearTimeout(timer); }
  if (resp.status === 401) { tokenCache.delete(VAULT_RES); throw Object.assign(new Error('Token rejected — run az login'), { needLogin: true }); }
  if (resp.status === 403) throw await forbiddenError(resp);
  if (resp.status === 404) throw Object.assign(new Error('Vault or item not found'), { notFound: true });
  if (!resp.ok) {
    let m = `Key Vault returned ${resp.status}`;
    try { const j = await resp.json(); m = (j.error && j.error.message) || m; } catch { /* ignore */ }
    throw new Error(m);
  }
  invalidateVault(vaultName);
  return resp.json();
}

// Update a secret's attributes (enabled / expires) on its current version.
app.patch('/api/vaults/:name/secrets/:secret', (req, res) => {
  const { name, secret } = req.params;
  if (!isValidName(name) || !isValidName(secret)) return res.status(400).json({ ok: false, error: 'Invalid name' });
  send(res, kvWrite(name, 'PATCH', `/secrets/${secret}?api-version=${KV_API}`, { attributes: buildAttrs(req.body) }));
});

// Set a secret's value (creates a new version), optionally with attributes.
app.put('/api/vaults/:name/secrets/:secret', (req, res) => {
  const { name, secret } = req.params;
  if (!isValidName(name) || !isValidName(secret)) return res.status(400).json({ ok: false, error: 'Invalid name' });
  const { value } = req.body || {};
  if (typeof value !== 'string' || !value.length) return res.status(400).json({ ok: false, error: 'A non-empty value is required' });
  const body = { value };
  const attrs = buildAttrs(req.body);
  if (Object.keys(attrs).length) body.attributes = attrs;
  send(res, kvWrite(name, 'PUT', `/secrets/${secret}?api-version=${KV_API}`, body));
});

// Update a certificate's attributes (enabled only — expiry is intrinsic to the cert).
app.patch('/api/vaults/:name/certificates/:cert', (req, res) => {
  const { name, cert } = req.params;
  if (!isValidName(name) || !isValidName(cert)) return res.status(400).json({ ok: false, error: 'Invalid name' });
  const attrs = {};
  if (typeof req.body.enabled === 'boolean') attrs.enabled = req.body.enabled;
  send(res, kvWrite(name, 'PATCH', `/certificates/${cert}?api-version=${KV_API}`, { attributes: attrs }));
});

// Turn a write failure into a precise, actionable reason. A 403 from Key Vault is
// either a network/firewall block (fix: VPN) or a real data-plane permission gap
// (fix: grant Set on secrets) — never conflate the two as a bare "forbidden".
function writeReason(e) {
  if (e.firewall) return 'blocked by the vault firewall — your IP is not allowed (connect to the corporate VPN)';
  if (e.forbidden) return 'no write permission — your identity can read but not Set secrets on this vault';
  return e.message || 'failed';
}

// Create one or many secrets in a vault. items: [{name, value}], optional common expires.
app.post('/api/vaults/:name/secrets-create', async (req, res) => {
  const { name } = req.params;
  if (!isValidName(name)) return res.status(400).json({ ok: false, error: 'Invalid vault name' });
  const { items, expires } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ ok: false, error: 'No secrets to create' });
  if (items.length > 500) return res.status(400).json({ ok: false, error: 'Too many (max 500)' });
  const attrs = buildAttrs({ expires });
  const results = await pool(items, async (it) => {
    const r = { name: it.name };
    try {
      if (!isValidName(it.name)) throw new Error('Invalid name (use letters, digits, hyphen)');
      if (typeof it.value !== 'string' || !it.value.length) throw new Error('Empty value');
      const body = { value: it.value };
      if (Object.keys(attrs).length) body.attributes = attrs;
      await kvWrite(name, 'PUT', `/secrets/${it.name}?api-version=${KV_API}`, body);
      return { ...r, ok: true };
    } catch (e) { return { ...r, ok: false, error: writeReason(e), firewall: !!e.firewall, forbidden: !!e.forbidden }; }
  }, 10);
  res.json({ ok: true, results });
});

// Batch update across one or many vaults. items: [{vault, kind, name}], op: {enabled?, expires?}
app.post('/api/batch', async (req, res) => {
  const { op = {}, items } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ ok: false, error: 'No items selected' });
  if (items.length > 500) return res.status(400).json({ ok: false, error: 'Too many items (max 500 per batch)' });
  const attrs = buildAttrs(op);
  const results = await pool(items, async (it) => {
    const r = { vault: it.vault, name: it.name, kind: it.kind };
    try {
      if (!isValidName(it.vault) || !isValidName(it.name)) throw new Error('Invalid name');
      if (it.kind === 'certificate') {
        if (op.expires) throw new Error("A certificate's expiry is fixed by the certificate itself");
        const a = {}; if (typeof op.enabled === 'boolean') a.enabled = op.enabled;
        if (!Object.keys(a).length) throw new Error('Nothing to change');
        await kvWrite(it.vault, 'PATCH', `/certificates/${it.name}?api-version=${KV_API}`, { attributes: a });
      } else {
        if (!Object.keys(attrs).length) throw new Error('Nothing to change');
        await kvWrite(it.vault, 'PATCH', `/secrets/${it.name}?api-version=${KV_API}`, { attributes: attrs });
      }
      return { ...r, ok: true };
    } catch (e) { return { ...r, ok: false, error: writeReason(e), firewall: !!e.firewall, forbidden: !!e.forbidden }; }
  }, 12);
  res.json({ ok: true, results });
});

// ---- API: AKS clusters (read-only monitoring: pods, logs, configmaps) -------
// Data plane goes straight to the Kubernetes API server over HTTPS, authenticated
// with an AAD token for the well-known managed-AAD server app — the same token
// `kubelogin` (azurecli mode) injects, so no kubelogin/kubectl binary is needed.

const https = require('https');
const AKS_AAD_SERVER_APP = '6dae42f8-4368-4678-94ff-3960e28e3630'; // Microsoft public constant
const getAksToken = () => getToken(AKS_AAD_SERVER_APP);
const K8S_NAME = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/; // DNS-1123-ish (namespaces, pods, cms)
const isK8sName = (v) => typeof v === 'string' && K8S_NAME.test(v);

// Cluster list — NEVER baked in. Two sources, merged: (1) the operator's file/env
// (AZBO_AKS_CLUSTERS / AZBO_AKS_CLUSTERS_FILE), and (2) a list the user pastes in the
// UI, persisted in their browser's localStorage and registered with this local server
// for the session. Each entry: { name, resourceGroup, subscription, env?, label? }.
const RG_RE = /^[\w.()-]{1,90}$/;
function clusterValid(c) {
  return c && isValidName(c.name) && RG_RE.test(c.resourceGroup || '') && SUB_RE.test(c.subscription || '');
}
function normalizeClusters(arr, source) {
  return (Array.isArray(arr) ? arr : []).filter((c) => c && c.name && c.resourceGroup && c.subscription)
    .map((c) => ({ name: String(c.name), resourceGroup: String(c.resourceGroup), subscription: String(c.subscription),
      env: c.env ? String(c.env) : '', label: c.label ? String(c.label) : String(c.name), configured: true, source }));
}
const AKS_CLUSTERS = (() => {
  let raw = process.env.AZBO_AKS_CLUSTERS;
  if (!raw && process.env.AZBO_AKS_CLUSTERS_FILE) {
    try { raw = require('fs').readFileSync(process.env.AZBO_AKS_CLUSTERS_FILE, 'utf8'); }
    catch (e) { console.warn('  AZBO_AKS_CLUSTERS_FILE could not be read:', e.message); }
  }
  if (!raw) return [];
  try { return normalizeClusters(JSON.parse(raw), 'file'); }
  catch { console.warn('  AZBO_AKS_CLUSTERS is not valid JSON — ignoring.'); return []; }
})();
let SESSION_CLUSTERS = [];   // set by the client via POST /api/aks/clusters (from its localStorage)

async function resolveSubId(nameOrId) {
  if (/^[0-9a-fA-F-]{36}$/.test(nameOrId)) return nameOrId;
  const subs = await listSubscriptions();
  const s = subs.find((x) => x.displayName === nameOrId || x.subscriptionId === nameOrId);
  return s ? s.subscriptionId : nameOrId;
}

// Cache each cluster's API server URL + CA (from listClusterUserCredential) for 30 min.
const aksCredCache = new Map();
async function aksCredential(c) {
  const key = `${c.subscription}/${c.resourceGroup}/${c.name}`;
  const hit = aksCredCache.get(key);
  if (hit && Date.now() - hit.at < 30 * 60 * 1000) return hit;
  const subId = await resolveSubId(c.subscription);
  const url = `/subscriptions/${subId}/resourceGroups/${c.resourceGroup}` +
              `/providers/Microsoft.ContainerService/managedClusters/${c.name}` +
              `/listClusterUserCredential?api-version=2024-05-01`;
  const out = await armFetch(url, { method: 'POST' });
  const kc = out.kubeconfigs && out.kubeconfigs[0];
  if (!kc || !kc.value) throw new Error('No kubeconfig returned for this cluster');
  const yaml = Buffer.from(kc.value, 'base64').toString('utf8');
  const server = (yaml.match(/server:\s*(\S+)/) || [])[1];
  const caB64 = (yaml.match(/certificate-authority-data:\s*(\S+)/) || [])[1];
  if (!server) throw new Error('Could not parse API server URL from kubeconfig');
  const cred = { server: server.replace(/\/+$/, ''),
    ca: caB64 ? Buffer.from(caB64, 'base64').toString('utf8') : undefined, at: Date.now() };
  aksCredCache.set(key, cred);
  return cred;
}

function k8sMsg(body) { try { return JSON.parse(body).message; } catch { return null; } }

// The "build" of a pod = its container image tag (e.g. registry/app:11.5.0387 → 11.5.0387).
// Digest-pinned images (@sha256:…) have no human tag; callers fall back to a version label.
function imageTag(img) {
  if (!img || img.includes('@')) return '';
  const repoTag = img.slice(img.lastIndexOf('/') + 1);
  const c = repoTag.indexOf(':');
  return c >= 0 ? repoTag.slice(c + 1) : '';
}

// One GET against a cluster's Kubernetes API. raw=true returns text (for pod logs).
function k8sGet(cred, pathQuery, { raw = false, timeout = 25000 } = {}) {
  return new Promise((resolve, reject) => {
    getAksToken().then((token) => {
      const u = new URL(cred.server + pathQuery);
      const req = https.request({
        hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'GET',
        // '*/*' for raw so the log subresource returns text/plain without tripping content negotiation
        headers: { Authorization: `Bearer ${token}`, Accept: raw ? '*/*' : 'application/json' },
        ca: cred.ca, timeout,
      }, (res) => {
        let data = ''; res.setEncoding('utf8');
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          const s = res.statusCode;
          if (s === 401) { tokenCache.delete(AKS_AAD_SERVER_APP); return reject(Object.assign(new Error('Token rejected — run az login'), { needLogin: true })); }
          if (s === 403) return reject(Object.assign(new Error(k8sMsg(data) || 'Forbidden'), { forbidden: true }));
          if (s === 404) return reject(Object.assign(new Error(k8sMsg(data) || 'Not found'), { notFound: true }));
          if (s >= 400) return reject(new Error(k8sMsg(data) || `Kubernetes returned ${s}`));
          try { resolve(raw ? data : (data ? JSON.parse(data) : null)); }
          catch (e) { reject(new Error('Failed to parse Kubernetes response: ' + e.message)); }
        });
      });
      req.on('error', (e) => {
        const code = e.code || '';
        const network = /ENOTFOUND|ETIMEDOUT|ECONNREFUSED|EAI_AGAIN|ECONNRESET|UNABLE_TO_VERIFY|SELF_SIGNED/.test(code + e.message);
        reject(Object.assign(new Error(network
          ? 'Cannot reach the cluster API server — it is private. Connect to the corporate VPN and retry.'
          : e.message), { network }));
      });
      req.on('timeout', () => req.destroy(Object.assign(new Error('Cluster API request timed out — is the VPN connected?'), { network: true })));
      req.end();
    }).catch(reject);
  });
}

// Discover clusters you have ARM read on (best-effort) and merge with the configured list.
const AKS_QUERY =
  "resources | where type =~ 'microsoft.containerservice/managedclusters' " +
  "| project name, resourceGroup, subscriptionId, " +
  "ver=tostring(properties.kubernetesVersion), " +
  "priv=tostring(properties.apiServerAccessProfile.enablePrivateCluster) | order by name asc";
async function discoverClusters() {
  try {
    const subIds = (await listSubscriptions()).map((s) => s.subscriptionId);
    const out = await armFetch('/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01', {
      method: 'POST', body: { subscriptions: subIds, query: AKS_QUERY, options: { resultFormat: 'objectArray', $top: 1000 } },
    });
    return (out.data || []).map((c) => ({ name: c.name, resourceGroup: c.resourceGroup,
      subscription: c.subscriptionId, version: c.ver, private: c.priv === 'true', configured: false }));
  } catch { return []; }
}

function clusterById(list, id) { return list.find((c) => c.name === id); }
async function aksList() {
  const discovered = await discoverClusters();
  const byKey = new Map();
  for (const c of discovered) byKey.set(c.name.toLowerCase(), c);
  for (const c of [...AKS_CLUSTERS, ...SESSION_CLUSTERS]) {   // configured (file then session) win + carry label/env
    const prev = byKey.get(c.name.toLowerCase()) || {};
    byKey.set(c.name.toLowerCase(), { ...prev, ...c });
  }
  return [...byKey.values()].sort((a, b) => (a.label || a.name).localeCompare(b.label || b.name));
}

app.get('/api/aks/clusters', (req, res) =>
  send(res, aksList().then((clusters) => ({ clusters,
    configured: AKS_CLUSTERS.length + SESSION_CLUSTERS.length, file: AKS_CLUSTERS.length, session: SESSION_CLUSTERS.length }))));

// Register the user's pasted cluster list for this session (from their localStorage).
// Replaces the previous session list; validated; localhost-only like the rest of the API.
app.post('/api/aks/clusters', (req, res) => {
  const { clusters } = req.body || {};
  if (!Array.isArray(clusters)) return res.status(400).json({ ok: false, error: 'clusters must be a JSON array' });
  if (clusters.length > 200) return res.status(400).json({ ok: false, error: 'Too many clusters (max 200)' });
  for (const c of clusters) {
    if (!c || !c.name || !c.resourceGroup || !c.subscription) return res.status(400).json({ ok: false, error: `Each entry needs name, resourceGroup, subscription (got: ${JSON.stringify(c).slice(0, 60)})` });
    if (!clusterValid(c)) return res.status(400).json({ ok: false, error: `Invalid cluster entry "${c.name}" — check name / resourceGroup / subscription` });
  }
  SESSION_CLUSTERS = normalizeClusters(clusters, 'session');
  aksCredCache.clear();                              // coordinates may have changed
  res.json({ ok: true, data: { count: SESSION_CLUSTERS.length } });
});

// Resolve a :cluster route param to a known cluster, or throw a typed 400/404.
async function getClusterChecked(name) {
  if (!isValidName(name)) throw Object.assign(new Error('Invalid cluster name'), { status: 400 });
  const c = clusterById(await aksList(), name);
  if (!c) throw Object.assign(new Error('Cluster is not in your configured/visible list'), { status: 404, notFound: true });
  return c;
}

app.get('/api/aks/:cluster/namespaces', (req, res) =>
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const out = await k8sGet(cred, '/api/v1/namespaces?limit=500');
    return (out.items || []).map((n) => ({ name: n.metadata.name, status: n.status && n.status.phase }));
  })()));

// Cluster-wide pod list (all namespaces) — each row carries its namespace.
app.get('/api/aks/:cluster/pods', (req, res) =>
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const out = await k8sGet(cred, '/api/v1/pods?limit=5000');
    return (out.items || []).map((p) => {
      const cs = (p.status && p.status.containerStatuses) || [];
      const spec = (p.spec && p.spec.containers) || [];
      const labels = p.metadata.labels || {};
      const build = imageTag((spec[0] || {}).image) || labels['app.kubernetes.io/version'] || labels.version || labels['tags.datadoghq.com/version'] || '';
      return { name: p.metadata.name, namespace: p.metadata.namespace, phase: p.status && p.status.phase, node: p.spec && p.spec.nodeName,
        build,
        restarts: cs.reduce((a, x) => a + (x.restartCount || 0), 0),
        ready: `${cs.filter((x) => x.ready).length}/${cs.length || spec.length}`,
        containers: spec.map((x) => x.name), created: p.metadata.creationTimestamp };
    });
  })()));

// Pod detail: labels (tags), images+tags, and declared env vars (names + inline values +
// secret/configmap references). Secret VALUES are never read — only the declarations.
app.get('/api/aks/:cluster/:ns/pods/:pod/detail', (req, res) => {
  const { ns, pod } = req.params;
  if (!isK8sName(ns) || !isK8sName(pod)) return res.status(400).json({ ok: false, error: 'Invalid namespace/pod' });
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const p = await k8sGet(cred, `/api/v1/namespaces/${ns}/pods/${pod}`);
    const md = p.metadata || {}, spec = p.spec || {};
    const inits = spec.initContainers || [];
    const descFrom = (vf) => {
      if (!vf) return null;
      if (vf.secretKeyRef) return { kind: 'secret', name: vf.secretKeyRef.name, key: vf.secretKeyRef.key };
      if (vf.configMapKeyRef) return { kind: 'configMap', name: vf.configMapKeyRef.name, key: vf.configMapKeyRef.key };
      if (vf.fieldRef) return { kind: 'field', key: vf.fieldRef.fieldPath };
      if (vf.resourceFieldRef) return { kind: 'resource', key: vf.resourceFieldRef.resource };
      return { kind: '?' };
    };
    const containers = [...(spec.containers || []), ...inits].map((c) => ({
      name: c.name, init: inits.includes(c), image: c.image, tag: imageTag(c.image),
      env: (c.env || []).map((e) => ({ name: e.name, value: e.value != null ? e.value : undefined, from: descFrom(e.valueFrom) })),
      envFrom: (c.envFrom || []).map((ef) => ({ kind: ef.secretRef ? 'secret' : ef.configMapRef ? 'configMap' : '?', name: (ef.secretRef || ef.configMapRef || {}).name, prefix: ef.prefix || '' })),
    }));
    return { name: md.name, namespace: md.namespace, node: spec.nodeName, labels: md.labels || {}, annotations: md.annotations || {}, containers };
  })());
});

// Cluster-wide configmap list (all namespaces).
app.get('/api/aks/:cluster/configmaps', (req, res) =>
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const out = await k8sGet(cred, '/api/v1/configmaps?limit=5000');
    return (out.items || []).map((m) => ({ name: m.metadata.name, namespace: m.metadata.namespace,
      keys: Object.keys(m.data || {}), created: m.metadata.creationTimestamp }));
  })()));

app.get('/api/aks/:cluster/:ns/pods', (req, res) => {
  if (!isK8sName(req.params.ns)) return res.status(400).json({ ok: false, error: 'Invalid namespace' });
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const out = await k8sGet(cred, `/api/v1/namespaces/${req.params.ns}/pods?limit=1000`);
    return (out.items || []).map((p) => {
      const cs = (p.status && p.status.containerStatuses) || [];
      const spec = (p.spec && p.spec.containers) || [];
      return { name: p.metadata.name, phase: p.status && p.status.phase, node: p.spec && p.spec.nodeName,
        restarts: cs.reduce((a, x) => a + (x.restartCount || 0), 0),
        ready: `${cs.filter((x) => x.ready).length}/${cs.length || spec.length}`,
        containers: spec.map((x) => x.name), created: p.metadata.creationTimestamp };
    });
  })());
});

app.get('/api/aks/:cluster/:ns/pods/:pod/log', (req, res) => {
  const { ns, pod } = req.params;
  if (!isK8sName(ns) || !isK8sName(pod)) return res.status(400).json({ ok: false, error: 'Invalid namespace/pod' });
  const q = new URLSearchParams();
  const tail = Math.min(20000, Math.max(1, Number(req.query.tailLines) || 1000));
  q.set('tailLines', String(tail));
  if (req.query.timestamps === 'true') q.set('timestamps', 'true');
  if (req.query.previous === 'true') q.set('previous', 'true');
  if (req.query.container && isK8sName(req.query.container)) q.set('container', req.query.container);
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const text = await k8sGet(cred, `/api/v1/namespaces/${ns}/pods/${pod}/log?${q.toString()}`, { raw: true });
    return { log: text, lines: text ? text.split('\n').length : 0 };
  })());
});

app.get('/api/aks/:cluster/:ns/configmaps', (req, res) => {
  if (!isK8sName(req.params.ns)) return res.status(400).json({ ok: false, error: 'Invalid namespace' });
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const out = await k8sGet(cred, `/api/v1/namespaces/${req.params.ns}/configmaps?limit=500`);
    return (out.items || []).map((m) => ({ name: m.metadata.name, keys: Object.keys(m.data || {}),
      created: m.metadata.creationTimestamp }));
  })());
});

app.get('/api/aks/:cluster/:ns/configmaps/:cm', (req, res) => {
  const { ns, cm } = req.params;
  if (!isK8sName(ns) || !isK8sName(cm)) return res.status(400).json({ ok: false, error: 'Invalid namespace/configmap' });
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const out = await k8sGet(cred, `/api/v1/namespaces/${ns}/configmaps/${cm}`);
    return { name: out.metadata.name, data: out.data || {} };
  })());
});

// Which Key Vaults does a pod reference? Three signals, best-effort:
//   1) CSI Secrets Store — pod volume → SecretProviderClass → keyvaultName (exact, declarative)
//   2) container env values containing a *.vault.azure.net URL
//   3) configmaps the pod consumes (envFrom / valueFrom / volume) whose values contain one
const VAULT_URL_RE = /\b([a-z0-9][a-z0-9-]{1,22}[a-z0-9])\.vault\.azure\.(?:net|cn|usgovcloudapi\.net)\b/gi;
function scanVaultRefs(text, set, source, srcMap) {
  if (typeof text !== 'string') return;
  let m; VAULT_URL_RE.lastIndex = 0;
  while ((m = VAULT_URL_RE.exec(text))) { const n = m[1].toLowerCase(); set.add(n); (srcMap[n] = srcMap[n] || new Set()).add(source); }
}
async function fetchSpc(cred, ns, name) {
  for (const v of ['v1', 'v1alpha1']) {
    try { return await k8sGet(cred, `/apis/secrets-store.csi.x-k8s.io/${v}/namespaces/${ns}/secretproviderclasses/${name}`); }
    catch (e) { if (e.notFound) continue; throw e; }
  }
  return null;
}

app.get('/api/aks/:cluster/:ns/pods/:pod/keyvaults', (req, res) => {
  const { ns, pod } = req.params;
  if (!isK8sName(ns) || !isK8sName(pod)) return res.status(400).json({ ok: false, error: 'Invalid namespace/pod' });
  send(res, (async () => {
    const cred = await aksCredential(await getClusterChecked(req.params.cluster));
    const p = await k8sGet(cred, `/api/v1/namespaces/${ns}/pods/${pod}`);
    const spec = p.spec || {};
    const containers = [...(spec.containers || []), ...(spec.initContainers || []), ...(spec.ephemeralContainers || [])];
    const set = new Set(), srcMap = {};
    // 2) inline env values
    for (const c of containers) for (const e of (c.env || [])) scanVaultRefs(e.value, set, 'env', srcMap);
    // configmaps the pod directly references (envFrom / valueFrom / configMap & projected volumes)
    const refNames = new Set();
    for (const c of containers) {
      for (const ef of (c.envFrom || [])) if (ef.configMapRef && ef.configMapRef.name) refNames.add(ef.configMapRef.name);
      for (const e of (c.env || [])) if (e.valueFrom && e.valueFrom.configMapKeyRef) refNames.add(e.valueFrom.configMapKeyRef.name);
    }
    for (const v of (spec.volumes || [])) {
      if (v.configMap && v.configMap.name) refNames.add(v.configMap.name);
      for (const s of ((v.projected && v.projected.sources) || [])) if (s.configMap && s.configMap.name) refNames.add(s.configMap.name);
    }
    // 3) List the namespace's configmaps (data included) and scan the ones that are either
    //    referenced by the pod, or name-related to it (the "<app>-appsettings" convention).
    const podLc = pod.toLowerCase();
    const cmBase = (n) => n.toLowerCase().replace(/-(appsettings|configmap|config|settings|secrets?|env|vars|values)$/, '');
    const scanned = [];
    try {
      const list = await k8sGet(cred, `/api/v1/namespaces/${ns}/configmaps?limit=500`);
      for (const m of (list.items || [])) {
        const nm = m.metadata.name, base = cmBase(nm);
        const related = refNames.has(nm) || podLc === base || podLc.startsWith(base + '-') || podLc.startsWith(nm.toLowerCase() + '-');
        if (!related) continue;
        scanned.push(nm);
        for (const val of Object.values(m.data || {})) scanVaultRefs(val, set, 'configmap:' + nm, srcMap);
      }
    } catch { /* can't list configmaps — skip that signal */ }
    // 1) CSI SecretProviderClasses referenced by the pod's volumes
    const spcNames = new Set();
    for (const v of (spec.volumes || [])) {
      const drv = (v.csi && v.csi.driver) || '';
      if (/secrets-store\.csi/.test(drv) && v.csi.volumeAttributes && v.csi.volumeAttributes.secretProviderClass)
        spcNames.add(v.csi.volumeAttributes.secretProviderClass);
    }
    const spcs = [];
    for (const spc of spcNames) {
      try {
        const o = await fetchSpc(cred, ns, spc);
        if (!o) { spcs.push({ name: spc, readable: false }); continue; }
        const params = (o.spec && o.spec.parameters) || {};
        const kv = params.keyvaultName || params.keyvaultname || params.keyVaultName;
        if (kv) { const n = String(kv).toLowerCase(); set.add(n); (srcMap[n] = srcMap[n] || new Set()).add('csi:' + spc); }
        for (const val of Object.values(params)) scanVaultRefs(String(val), set, 'csi:' + spc, srcMap);  // objects YAML etc.
        spcs.push({ name: spc, readable: true, vault: kv ? String(kv).toLowerCase() : null });
      } catch (e) {
        // The CRD is often unreadable, but a SecretProviderClass is commonly named after its
        // vault — if that name matches a vault you can see, surface it (no false positives).
        let inferred = null;
        try { const mv = await findVaultMeta(spc); if (mv) { const n = mv.name.toLowerCase(); set.add(n); (srcMap[n] = srcMap[n] || new Set()).add('csi:' + spc + ' (by name)'); inferred = mv.name; } } catch { /* ignore */ }
        spcs.push({ name: spc, readable: false, forbidden: !!e.forbidden, inferredVault: inferred });
      }
    }
    // 4) Secrets the pod consumes that are synced from a Key Vault by External Secrets
    //    Operator. We read only secret METADATA (never values) to find the owning
    //    ExternalSecret, then resolve its SecretStore's azurekv vaultUrl when readable.
    const secretNames = new Set();
    for (const c of containers) {
      for (const ef of (c.envFrom || [])) if (ef.secretRef && ef.secretRef.name) secretNames.add(ef.secretRef.name);
      for (const e of (c.env || [])) if (e.valueFrom && e.valueFrom.secretKeyRef) secretNames.add(e.valueFrom.secretKeyRef.name);
    }
    for (const v of (spec.volumes || [])) {
      if (v.secret && v.secret.secretName) secretNames.add(v.secret.secretName);
      for (const s of ((v.projected && v.projected.sources) || [])) if (s.secret && s.secret.name) secretNames.add(s.secret.name);
    }
    const esNames = new Set();
    for (const sn of secretNames) {
      try {
        const s = await k8sGet(cred, `/api/v1/namespaces/${ns}/secrets/${sn}`);   // metadata only is used below
        const md = s.metadata || {};
        const owner = (md.ownerReferences || []).find((o) => o.kind === 'ExternalSecret');
        const eso = owner || (md.labels && md.labels['reconcile.external-secrets.io/managed'] === 'true') ||
          Object.keys(md.annotations || {}).some((a) => a.startsWith('reconcile.external-secrets.io/'));
        if (eso) esNames.add(owner ? owner.name : sn);
      } catch { /* can't read secret metadata — skip */ }
    }
    const externalSecrets = [];
    const getCRD = async (path) => { for (const ver of ['v1', 'v1beta1']) { try { return await k8sGet(cred, path.replace('{v}', ver)); } catch (e) { if (e.notFound) continue; throw e; } } return null; };
    for (const esn of esNames) {
      const entry = { externalSecret: esn, vault: null, resolvable: false, reason: null };
      try {
        const es = await getCRD(`/apis/external-secrets.io/{v}/namespaces/${ns}/externalsecrets/${esn}`);
        const ref = (es && es.spec && es.spec.secretStoreRef) || {};
        const storePath = ref.kind === 'ClusterSecretStore'
          ? `/apis/external-secrets.io/{v}/clustersecretstores/${ref.name}`
          : `/apis/external-secrets.io/{v}/namespaces/${ns}/secretstores/${ref.name}`;
        const store = ref.name ? await getCRD(storePath) : null;
        const akv = store && store.spec && store.spec.provider && store.spec.provider.azurekv;
        const url = akv && (akv.vaultUrl || akv.vaultUri);
        const m = url && /([a-z0-9][a-z0-9-]{1,22}[a-z0-9])\.vault\.azure\./i.exec(url);
        if (m) { const n = m[1].toLowerCase(); set.add(n); (srcMap[n] = srcMap[n] || new Set()).add('eso:' + esn); entry.vault = n; entry.resolvable = true; }
        else entry.reason = 'store has no azurekv vaultUrl';
      } catch (e) { entry.reason = e.forbidden ? 'needs read on externalsecrets / secretstores' : (e.message || 'unreadable'); }
      externalSecrets.push(entry);
    }
    const vaults = [...set].sort().map((name) => ({ name, sources: [...(srcMap[name] || [])] }));
    return { vaults, configmapsScanned: scanned, spcs, externalSecrets };
  })());
});

// Interactive shell INTO a pod, in the browser. The browser opens a WebSocket to us;
// we open an upstream WebSocket to the Kubernetes `exec` endpoint (CA + AAD bearer
// token) and bridge the channel-framed streams. No kubectl needed. The API server
// enforces Kubernetes RBAC (pods/exec) — this grants nothing the identity lacks.
const { WebSocketServer, WebSocket } = require('ws');
const execWss = new WebSocketServer({ noServer: true });

function attachExecWss(server) {
  server.on('upgrade', (req, socket, head) => {
    let url; try { url = new URL(req.url, 'http://localhost'); } catch { socket.destroy(); return; }
    if (url.pathname !== '/ws/aks/exec') { socket.destroy(); return; }
    execWss.handleUpgrade(req, socket, head, (client) => bridgeExec(client, url.searchParams));
  });
}

async function bridgeExec(client, params) {
  const clusterName = params.get('cluster'), ns = params.get('ns'), pod = params.get('pod');
  const container = params.get('container') || null;
  const tell = (m) => { try { if (client.readyState === 1) client.send(m); } catch { /* ignore */ } };
  if (!isValidName(clusterName || '') || !isK8sName(ns || '') || !isK8sName(pod || '') || (container && !isK8sName(container))) {
    tell('\r\n\x1b[31mInvalid cluster/namespace/pod.\x1b[0m\r\n'); client.close(); return;
  }
  let cred, token;
  try {
    const c = clusterById(await aksList(), clusterName);
    if (!c) throw new Error('Cluster is not in your configured/visible list');
    cred = await aksCredential(c);
    token = await getAksToken();
  } catch (e) {
    tell('\r\n\x1b[31m' + (e.network ? 'Cannot reach the cluster — connect to the VPN.' : (e.message || 'auth failed')) + '\x1b[0m\r\n');
    client.close(); return;
  }
  const q = new URLSearchParams();
  q.set('stdin', 'true'); q.set('stdout', 'true'); q.set('stderr', 'true'); q.set('tty', 'true');
  if (container) q.set('container', container);
  // Prefer bash, fall back to ash/sh — one exec, the shell picks what exists.
  for (const part of ['/bin/sh', '-c', 'clear; (bash || ash || sh)']) q.append('command', part);
  const wsUrl = cred.server.replace(/^https:/, 'wss:') + `/api/v1/namespaces/${ns}/pods/${pod}/exec?` + q.toString();

  const upstream = new WebSocket(wsUrl, ['v4.channel.k8s.io', 'channel.k8s.io'], {
    headers: { Authorization: `Bearer ${token}` }, ca: cred.ca,
  });
  let handled = false;   // so the generic 'error' doesn't double-report a decoded HTTP status

  // The exec handshake is plain HTTP until it upgrades; decode a non-101 status precisely.
  upstream.on('unexpected-response', (reqU, resU) => {
    handled = true;
    let body = ''; resU.on('data', (d) => { body += d; }); resU.on('end', () => {
      let msg; try { msg = JSON.parse(body).message; } catch { /* ignore */ }
      const s = resU.statusCode;
      const friendly = s === 401 ? 'Not authorized — token rejected. Run az login (and check the cluster is managed-AAD).'
        : s === 403 ? 'Forbidden — your identity lacks Kubernetes "pods/exec" permission in this namespace.'
        : s === 404 ? 'Pod, namespace or container not found.'
        : (msg || `Kubernetes returned ${s}`);
      tell('\r\n\x1b[31m' + friendly + '\x1b[0m\r\n'); try { client.close(); } catch { /* ignore */ }
    });
  });

  upstream.on('open', () => tell(`\x1b[32m● connected to ${ns}/${pod}${container ? ' [' + container + ']' : ''}\x1b[0m\r\n`));
  upstream.on('message', (data) => {
    if (!data || !data.length) return;
    const ch = data[0], payload = data.subarray(1);     // channel: 1=stdout 2=stderr 3=error/status
    if (ch === 1 || ch === 2) { if (client.readyState === 1) client.send(payload); }
    else if (ch === 3) { try { const j = JSON.parse(payload.toString()); if (j.status === 'Failure' && j.message) tell('\r\n\x1b[31m' + j.message + '\x1b[0m\r\n'); } catch { /* ignore */ } }
  });
  upstream.on('close', () => { tell('\r\n\x1b[33m● session closed\x1b[0m\r\n'); try { client.close(); } catch { /* ignore */ } });
  upstream.on('error', (e) => { if (handled) return; tell('\r\n\x1b[31m' + (e.message || 'connection error — is the VPN connected?') + '\x1b[0m\r\n'); try { client.close(); } catch { /* ignore */ } });

  client.on('message', (msg, isBinary) => {
    if (upstream.readyState !== 1) return;
    if (isBinary) { upstream.send(Buffer.concat([Buffer.from([0]), msg])); return; }   // channel 0 = stdin
    try { const j = JSON.parse(msg.toString());                                         // text = control (resize)
      if (j.type === 'resize') upstream.send(Buffer.concat([Buffer.from([4]), Buffer.from(JSON.stringify({ Width: j.cols, Height: j.rows }))]));
    } catch { /* ignore */ }
  });
  client.on('close', () => { try { upstream.close(); } catch { /* ignore */ } });
}

// ---- fallback --------------------------------------------------------------

app.get('/api/health', (req, res) => res.json({ ok: true, az: AZ }));

// Optional, org-specific UI config — supplied by the operator via env vars, never baked in.
// AZBO_ENV_RULES: JSON like [["dev","Dev"],["prd","Prod"]] mapping name patterns to labels.
const ENV_RULES = (() => {
  try { return process.env.AZBO_ENV_RULES ? JSON.parse(process.env.AZBO_ENV_RULES) : null; }
  catch { console.warn('  AZBO_ENV_RULES is not valid JSON — ignoring.'); return null; }
})();
const PKG_VERSION = (() => { try { return require('./package.json').version; } catch { return null; } })();
app.get('/api/config', (req, res) =>
  res.json({ ok: true, data: { envRules: ENV_RULES, title: process.env.AZBO_TITLE || null,
    version: PKG_VERSION, protectedTags: PROTECTED_TAGS, aksConfigured: AKS_CLUSTERS.length } }));

function openBrowser(url) {
  if (process.env.AZBO_NO_OPEN) return;
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  try { require('child_process').spawn(cmd, [url], { stdio: 'ignore', detached: true, shell: process.platform === 'win32' }).unref(); }
  catch { /* opening is best-effort */ }
}

function start(port, attemptsLeft = 12) {
  const server = app.listen(port, HOST, () => {
    const url = `http://${HOST}:${port}`;
    console.log(`\n  akv-manager → ${url}`);
    console.log(`  Auth: your current 'az login' identity (run 'az login' if signed out).`);
    console.log(`  Stop with Ctrl-C.\n`);
    openBrowser(url);
  });
  attachExecWss(server);   // browser ⇆ Kubernetes exec bridge for the in-pod terminal
  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE' && attemptsLeft > 0) {
      console.log(`  Port ${port} in use, trying ${port + 1}…`);
      start(port + 1, attemptsLeft - 1);
    } else { console.error(`  Failed to start: ${e.message}`); process.exit(1); }
  });
}
start(PORT);
