# Deploying FairProof to a server

This is the procedure used for the live instance at **https://fairprocure.xyz**,
written from what actually worked on a 2 vCPU / 3.7 GB AWS EC2 box.

**Read the warning first.** It changes how you deploy.

---

## The warning

`npm run dashboard:sync` writes **16 role private keys** into the browser bundle
so the dashboard can sign as any role without a wallet. That is fine on a
laptop. On a public URL it means:

> **Every visitor holds every role** — procuring authority, certifying body, and
> a 3-of-4 council majority. Anyone who opens the page can cancel a tender,
> award one, or pause the protocol. There is no login; the role switcher is a
> view toggle, not a permission.

There is also **one shared chain**: one visitor cancelling a tender destroys
another visitor's walkthrough, and there is no per-visitor reset.

So a public instance is a **sandbox, not a product**. Pick one:

- **Gate it** with HTTP basic auth and hand the password to reviewers. Fifteen
  minutes, and it neutralises the key exposure, the RPC exposure and the
  shared-state problem at once, because you know who is on it. Recommended.
- **Leave it open** and accept that state will be broken by visitors. Then
  re-seed immediately before any demo.
- **Do it properly**: strip the keys from the bundle, keep only
  `anonymousSigner()` for bidder actions, and move authority and committee
  signing behind a server that holds those keys. That is a few days of work and
  it changes the trust story you present.

---

## 1. Provision

Minimum that worked: **2 vCPU, 3.7 GB RAM, 38 GB disk**, Ubuntu 24.04+.

```bash
# Swap first — four JVMs plus nginx on 3.7 GB is tight without it.
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab

sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 nginx apache2-utils rsync curl
sudo usermod -aG docker $USER      # log out and back in

curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

`circom` is **not** needed on the server if you build the circuits elsewhere and
copy the artifacts (see step 2).

---

## 2. Get the code and the artifacts onto the box

The circuit build (~330 MB) and the ptau file are not in git. Either run the
full `npm run setup` on the server, or — much faster — build locally and copy:

```bash
rsync -az --info=stats2 \
  --exclude node_modules --exclude .git \
  --exclude 'infrastructure/besu/nodes/*/data' \
  --exclude infrastructure/replica-run \
  --exclude apps/dashboard/dist \
  --exclude apps/dashboard/public/committee-dealings \
  --exclude apps/dashboard/public/bidder-receipts \
  ./ user@YOUR_HOST:~/fairproof/
```

Exclude the local chain data — the server generates its own genesis. On the
server:

```bash
cd ~/fairproof
npm ci --no-audit --no-fund
npm run crypto:build
```

---

## 3. Cap the validator heap

The committed compose file allows each validator `-Xmx1g`. Four of those will
not fit in 3.7 GB alongside nginx and three stores. Create
`infrastructure/besu/docker-compose.override.yml`:

```yaml
services:
  validator-1: { environment: { BESU_OPTS: "-Xmx448m -Xms128m" } }
  validator-2: { environment: { BESU_OPTS: "-Xmx448m -Xms128m" } }
  validator-3: { environment: { BESU_OPTS: "-Xmx448m -Xms128m" } }
  validator-4: { environment: { BESU_OPTS: "-Xmx448m -Xms128m" } }
```

Measured result: **~335 MB RSS per validator**, with 1.7 GB still free. A private
chain of a few thousand blocks does not need a gigabyte of heap.

---

## 4. Chain, contracts, stores

```bash
npm run network:setup
UID=$(id -u) GID=$(id -g) docker compose \
  -f infrastructure/besu/docker-compose.yml \
  -f infrastructure/besu/docker-compose.override.yml up -d
npm run network:health            # expect HEALTHY, 4/4

npm run contracts:compile
npm run deploy                    # ~2 min: real 3-of-4 governance + 60s timelock
npm run dashboard:sync
```

Run the replicas under systemd so they survive a reboot —
`/etc/systemd/system/fairproof-replicas.service`:

```ini
[Unit]
Description=FairProof ciphertext-store replicas (3, quorum 2)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=ubuntu
WorkingDirectory=/home/ubuntu/fairproof
ExecStart=/usr/bin/npm run replicas:start
ExecStop=/usr/bin/npm run replicas:stop
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now fairproof-replicas
npm run replicas:status           # expect 3/3
```

---

## 5. Build the bundle for a public origin

**This is the step people get wrong.** `contracts.json` records the loopback
addresses the sync script saw. Served from a host, `127.0.0.1` is the
*visitor's* own machine, so every read fails and the app dead-ends.

Build with **origin-relative** endpoint templates:

```bash
export VITE_RPC_URL_TEMPLATE="/rpc/{n}"
export VITE_STORE_URL_TEMPLATE="/store/{n}"
NODE_OPTIONS=--max-old-space-size=1400 npm run dashboard:build
```

`{n}` is 1-based — validators 1-4, replicas 1-3. A template beginning with `/`
is resolved against whatever origin served the page, so **the same build works
on an IP, behind an SSH tunnel, and on a domain with TLS, without rebuilding**.
Absolute templates (`https://host/rpc/{n}`) still work if the chain is proxied
by a different host.

Publish it:

```bash
sudo mkdir -p /var/www/fairproof
sudo rsync -a --delete apps/dashboard/dist/ /var/www/fairproof/
sudo chown -R www-data:www-data /var/www/fairproof
```

---

## 6. nginx

`/etc/nginx/sites-available/fairproof`:

```nginx
server {
    listen 80;
    server_name YOUR_DOMAIN;

    # Strongly recommended. Delete these two lines only if you accept that
    # every visitor holds all 16 role private keys.
    auth_basic           "FairProof";
    auth_basic_user_file /etc/nginx/fairproof.htpasswd;

    root /var/www/fairproof;
    index index.html;

    location /circuits/ { expires 30d; add_header Cache-Control "public, immutable"; try_files $uri =404; }
    location /assets/   { expires 7d; try_files $uri =404; }
    location /          { try_files $uri $uri/ /index.html; }

    location = /rpc/1 { proxy_pass http://127.0.0.1:8545/; include /etc/nginx/fairproof-proxy.conf; }
    location = /rpc/2 { proxy_pass http://127.0.0.1:8546/; include /etc/nginx/fairproof-proxy.conf; }
    location = /rpc/3 { proxy_pass http://127.0.0.1:8547/; include /etc/nginx/fairproof-proxy.conf; }
    location = /rpc/4 { proxy_pass http://127.0.0.1:8548/; include /etc/nginx/fairproof-proxy.conf; }

    location /store/1/ { proxy_pass http://127.0.0.1:8101/; include /etc/nginx/fairproof-proxy.conf; }
    location /store/2/ { proxy_pass http://127.0.0.1:8102/; include /etc/nginx/fairproof-proxy.conf; }
    location /store/3/ { proxy_pass http://127.0.0.1:8103/; include /etc/nginx/fairproof-proxy.conf; }

    client_max_body_size 4m;
}
```

`/etc/nginx/fairproof-proxy.conf`:

```nginx
proxy_http_version 1.1;
proxy_set_header Host            $host;
proxy_set_header X-Real-IP       $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header Upgrade         $http_upgrade;
proxy_set_header Connection      "upgrade";
proxy_read_timeout 120s;

# The stores set permissive CORS headers of their own for a cross-origin
# dashboard. Proxied same-origin these become duplicates, which browsers treat
# as a malformed header rather than a permissive one.
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
```

```bash
sudo htpasswd -bc /etc/nginx/fairproof.htpasswd reviewer 'CHOOSE_A_PASSWORD'
sudo ln -sf /etc/nginx/sites-available/fairproof /etc/nginx/sites-enabled/fairproof
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

**Proxying the RPC is not cosmetic.** The validators expose
`ADMIN`, `DEBUG` and `TXPOOL` with `--host-allowlist=*`, no authentication and a
zero gas price. Never open 8545-8548 to the internet; let only nginx reach them.

---

## 7. TLS

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d YOUR_DOMAIN
```

**A bare IP cannot have a trusted certificate** — no public CA issues them for
addresses. You need a hostname. Because the bundle is origin-relative, adding
TLS needs **no rebuild**.

Open **80 and 443** in your cloud firewall. On AWS that is the instance's
security group, not `ufw`: with only port 22 allowed, nginx answers correctly on
the box and is unreachable from outside, which looks exactly like a broken
deploy.

---

## 8. Seed and verify

```bash
npm run tender -- --window 3600

# tender:complete and tender write seed material into the source tree;
# nginx serves /var/www, so publish it across:
for d in committee-dealings bidder-receipts; do
  [ -d "apps/dashboard/public/$d" ] && sudo rsync -a "apps/dashboard/public/$d/" "/var/www/fairproof/$d/"
done
sudo chown -R www-data:www-data /var/www/fairproof
```

Then check from **outside** the box:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_DOMAIN/
curl -s -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
     https://YOUR_DOMAIN/rpc/1
curl -s https://YOUR_DOMAIN/store/1/health

DASHBOARD_URL="https://YOUR_DOMAIN/" npm run test:ui
```

`test:ui` against the live URL is the check that matters: it asserts all five
workspaces render with no console errors, which a build cannot tell you.

---

## Operating notes

- **Re-seed before any demo.** If the instance is ungated, assume state has been
  altered.
- **`npm run deploy` wipes every tender.** Re-run `npm run tender` after it.
- **Certificates renew** via certbot's timer; confirm with
  `sudo certbot renew --dry-run`.
- **Watch memory** with `free -h` and `docker stats --no-stream`. If a validator
  is OOM-killed, lower `-Xmx` further rather than adding validators.
- **Bandwidth**: each fresh visitor downloads ~68 MB of proving keys. The
  `immutable` cache header on `/circuits/` matters more than instance size.
