# Development certificates

`apps/demo-server` serves https when `SERVER_TLS_CERT` and `SERVER_TLS_KEY` name a pair. Some passkey
providers refuse `localhost` as a relying party whatever the scheme (Proton Pass:
`InsecureLocalhostNotAllowed`), so to try one, serve the demo under another name. `bun index.html` takes
no certificate, so `apps/demo-vue` stays on http.

```sh
sudo pacman -S mkcert   # or: apt install mkcert
mkcert -install         # once per machine: trusts the local CA
mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1 "*.local.dev"
chmod 600 key.pem
echo "127.0.0.1 oidcraft.local.dev" | sudo tee -a /etc/hosts
```

Then in `.env`, with paths relative to `apps/demo-server`:

```sh
OIDCRAFT_ISSUER=https://oidcraft.local.dev:3001
OIDCRAFT_PUBLIC_ISSUER=https://oidcraft.local.dev:3001
SERVER_HOSTNAME=oidcraft.local.dev
SERVER_TLS_CERT=../../.cert/cert.pem
SERVER_TLS_KEY=../../.cert/key.pem
```

Passkeys belong to the host they were made on: none made under `localhost` sign in under this name.

`apps/demo-react` serves https from this pair too when it is present. Its server-side render calls the
provider, and certificate checks stay on: Bun trusts the system's CAs, which `mkcert -install` joined.
A provider behind any other self-signed certificate needs its CA trusted, or named in
`NODE_EXTRA_CA_CERTS`.
The `*.pem` files are git-ignored.
