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
| `deploy/rulescope-demo.service`, `.timer` | Nightly rebuild from the current `main`. |

## Deploy on a small Linux machine or container

Put it behind a reverse proxy that terminates TLS. Run as root:

```bash
apt-get update && apt-get install -y --no-install-recommends git python3 caddy ca-certificates
useradd --system --home-dir /srv/rulescope-demo --shell /usr/sbin/nologin rsdemo
install -d -o rsdemo -g rsdemo /srv/rulescope-demo /opt/rulescope-fortigate /var/cache/rulescope-demo
runuser -u rsdemo -- git clone https://github.com/mrpash89/rulescope-fortigate.git /opt/rulescope-fortigate
printf 'SITE_URL=https://demo.example.com\nADVISORIES=off\n' > /etc/rulescope-demo.env
cp /opt/rulescope-fortigate/website/deploy/Caddyfile /etc/caddy/Caddyfile
cp /opt/rulescope-fortigate/website/deploy/rulescope-demo.service /opt/rulescope-fortigate/website/deploy/rulescope-demo.timer /etc/systemd/system/
systemctl daemon-reload
systemctl start rulescope-demo.service          # first build
systemctl enable --now rulescope-demo.timer
systemctl restart caddy
curl -sI http://127.0.0.1/ | head -1            # expect: HTTP/1.1 200 OK
```

The sample reports are kept out of search engines by `robots.txt`: they describe weaknesses of
fictional firewalls and would read like a real exposed report in search results.
