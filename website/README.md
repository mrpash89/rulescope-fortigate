# Demo website

The public demo is a static site: a landing page plus real RuleScope output built from synthetic
configs. Nothing a visitor sends ever reaches RuleScope.

```bash
python3 website/build.py --out /tmp/rulescope-site --site-url http://localhost:8000
python3 -m http.server -d /tmp/rulescope-site/current 8000      # then open http://localhost:8000
```

| File | Purpose |
|---|---|
| `index.html` | Landing page template. `build.py` fills in the version and the real findings of the sample firewall. |
| `build.py` | Runs `examples/make_demo.py`, renders the landing page, checks the result and switches the `current` link. A failed build leaves the published site as it was. |
| `deploy/Caddyfile` | Caddy config for the machine that holds the files: static files, security headers, `GET` and `HEAD` only. |
| `deploy/rulescope-demo-fetch.service` | Sets the checkout to the current `main`, as its own user. |
| `deploy/rulescope-demo.service`, `.timer` | Nightly rebuild, as a second user that can only read the checkout and has no network. |

## Deploy on a small Linux machine or container

Put it behind a reverse proxy that terminates TLS. Run as root:

```bash
apt-get update && apt-get install -y --no-install-recommends git python3 caddy ca-certificates unattended-upgrades
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin rsfetch     # owns the checkout
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin rsdemo      # builds the site
install -d -o rsfetch -g rsfetch /opt/rulescope-fortigate
install -d -o rsdemo -g rsdemo /srv/rulescope-demo /var/cache/rulescope-demo
runuser -u rsfetch -- git clone https://github.com/mrpash89/rulescope-fortigate.git /opt/rulescope-fortigate
printf 'SITE_URL=https://demo.example.com\nADVISORIES=off\n' > /etc/rulescope-demo.env
chmod 600 /etc/rulescope-demo.env
cd /opt/rulescope-fortigate/website/deploy
cp Caddyfile /etc/caddy/Caddyfile
cp rulescope-demo-fetch.service rulescope-demo.service rulescope-demo.timer /etc/systemd/system/
systemctl daemon-reload
systemctl start rulescope-demo.service          # updates the checkout, then builds
systemctl --no-pager status rulescope-demo-fetch.service rulescope-demo.service | grep -E 'Loaded|Active|status='
systemctl enable --now rulescope-demo.timer
systemctl restart caddy
curl -sI http://127.0.0.1/ | head -1            # expect: HTTP/1.1 200 OK
```

## How the nightly rebuild is contained

The machine runs code from a public repository every night, so a bad merge must not be able to do
much:

- **Two users.** `rsfetch` owns the checkout and only runs git (no hooks, checkout reset to exactly
  `main`). `rsdemo` runs the build and can only read the checkout, so code from the repository cannot
  change what runs the next night.
- **No network for the build.** It needs none. The unit has `PrivateNetwork=yes`.
- **Limits.** Five minutes, 256 MB, no capabilities, a system call filter, read-only file system
  except the site folder.
- **Installed copies.** The Caddy config and the units in `/etc` are copies owned by root. A change to
  them in the repository does nothing until an administrator copies them again.
- **No links.** The build refuses to publish a symbolic link; the web server would follow it.
- **Firewall.** Allow the machine outbound DNS and TCP 80 and 443 only, and nothing towards your own
  networks.

Protect `main` (pull requests and the `ci` check required): whatever is merged there is on the site
the next night.

The sample pages ask search engines not to index them (a `noindex` tag in each page and an
`X-Robots-Tag` header): they describe weaknesses of fictional firewalls and would read like a real
exposed report in search results.
