#!/usr/bin/env bash
# RyProx installer.
#
#   curl -fsSL https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh | sudo bash
#
# To review it before running:
#   curl -fsSLO https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh
#   less install.sh
#   sudo bash install.sh
#
# It asks a few questions, installs RyProx with Docker or as a system
# service, sets up HTTPS, and prints your first-time setup code.
# Run it again later to update.
#
# Options (all optional; anything not given is asked for):
#   --docker | --native     how to install
#   --signin-domain NAME    where people sign in to private sites, e.g. login.example.com
#   --dashboard-domain NAME also serve the dashboard at https://NAME (default: local only)
#   --email ADDRESS         email for Let's Encrypt (turns on automatic HTTPS)
#   --staging | --no-staging  start with test certificates (default: yes)
#   --version vX.Y.Z        install a specific version (default: newest)
#   --yes                   don't ask, use the answers given and the defaults
#   --dry-run               show what would be done, change nothing

set -euo pipefail

REPO="RylanQ/ryprox"
IMAGE="ghcr.io/rylanq/ryprox"
BIN=/usr/local/bin/ryprox
DATA=/var/lib/ryprox
UNIT=/etc/systemd/system/ryprox.service
CONTAINER=ryprox
VOLUME=ryprox-data
ADMIN_PORT=8081

METHOD="" DOMAIN="" DASHBOARD="" EMAIL="" STAGING="" VERSION="" YES=0 DRY=0

# ---------- output ----------
if [ -t 1 ]; then
  B=$'\e[1m' D=$'\e[2m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'
else
  B="" D="" G="" Y="" R="" N=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sError:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# run executes a command, or just prints it in --dry-run mode.
run() {
  if [ "$DRY" = 1 ]; then printf '  %s[dry-run]%s %s\n' "$D" "$N" "$*" >&2; return 0; fi
  "$@"
}

# ---------- questions ----------
# Prompts read from the terminal, so they work with "curl | sudo bash".
TTY=""
if [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then TTY=/dev/tty; fi

ask() { # ask VAR "Question" "default"
  local __var=$1 q=$2 def=${3:-} ans=""
  if [ "$YES" = 1 ] || [ -z "$TTY" ]; then
    printf -v "$__var" '%s' "$def"; return
  fi
  if [ -n "$def" ]; then printf '%s %s[%s]%s: ' "$q" "$D" "$def" "$N" > /dev/tty
  else printf '%s: ' "$q" > /dev/tty; fi
  IFS= read -r ans < "$TTY" || true
  printf -v "$__var" '%s' "${ans:-$def}"
}

confirm() { # confirm "Question" y|n  → exit status
  local q=$1 def=${2:-y} ans hint="[Y/n]"
  if [ "$def" = n ]; then hint="[y/N]"; fi
  if [ "$YES" = 1 ] || [ -z "$TTY" ]; then [ "$def" = y ]; return; fi
  printf '%s %s%s%s: ' "$q" "$D" "$hint" "$N" > /dev/tty
  IFS= read -r ans < "$TTY" || true
  ans=${ans:-$def}
  case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

valid_domain() {
  [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]
}
valid_email() { [[ $1 =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }

# ---------- arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) METHOD=docker ;;
    --native) METHOD=native ;;
    --signin-domain|--domain) DOMAIN=${2:?--signin-domain needs a value}; shift ;;
    --dashboard-domain) DASHBOARD=${2:?--dashboard-domain needs a value}; shift ;;
    --email) EMAIL=${2:?--email needs a value}; shift ;;
    --staging) STAGING=yes ;;
    --no-staging) STAGING=no ;;
    --version) VERSION=${2:?--version needs a value}; shift ;;
    --yes|-y) YES=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) say "See the comments at the top of install.sh."; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# ---------- checks ----------
printf '\n%sRyProx installer%s\n' "$B" "$N"
say "Routes your domains to your services, with automatic HTTPS."

if [ "$DRY" != 1 ] && [ "$(id -u)" -ne 0 ]; then
  die "please run as root, e.g.: curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash"
fi
[ "$(uname -s)" = Linux ] || die "this installer supports Linux. On other systems, see the guide for manual install."
command -v curl >/dev/null || die "curl is needed; install it first (e.g. apt install curl)"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7*) ARCH=armv7 ;;
  *) die "unsupported CPU type: $(uname -m)" ;;
esac

HAVE_DOCKER=0
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then HAVE_DOCKER=1; fi
HAVE_SYSTEMD=0
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then HAVE_SYSTEMD=1; fi

# Existing install? Then this is an update.
EXISTING=""
if [ "$HAVE_DOCKER" = 1 ] && docker container inspect "$CONTAINER" >/dev/null 2>&1; then EXISTING=docker
elif [ -f "$UNIT" ]; then EXISTING=native; fi

# ---------- version ----------
latest_version() {
  # Newest release, including pre-releases while RyProx is in alpha.
  curl -fsSL --max-time 15 "https://api.github.com/repos/$REPO/releases?per_page=1" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1
}
if [ -z "$VERSION" ]; then VERSION=$(latest_version || true); fi

# ---------- method ----------
step "How to install"
if [ -n "$EXISTING" ]; then
  METHOD=$EXISTING
  say "  RyProx is already installed (${EXISTING}). This will update it and keep your settings."
fi
if [ -z "$METHOD" ]; then
  if [ "$HAVE_DOCKER" = 1 ] && [ "$HAVE_SYSTEMD" = 1 ]; then
    say "  Docker keeps RyProx in its own container; a system service runs it directly."
    if confirm "  Install with Docker?" y; then METHOD=docker; else METHOD=native; fi
  elif [ "$HAVE_DOCKER" = 1 ]; then METHOD=docker
  elif [ "$HAVE_SYSTEMD" = 1 ]; then METHOD=native
  elif [ "$DRY" = 1 ]; then METHOD=docker
  else die "this machine has neither Docker nor systemd. Install Docker first: https://docs.docker.com/engine/install/"
  fi
fi
if [ "$DRY" != 1 ]; then
  if [ "$METHOD" = docker ] && [ "$HAVE_DOCKER" != 1 ]; then die "Docker isn't installed or isn't running."; fi
  if [ "$METHOD" = native ] && [ "$HAVE_SYSTEMD" != 1 ]; then die "a system service needs systemd; use --docker instead."; fi
fi
if [ "$METHOD" = native ] && [ -z "$VERSION" ]; then
  die "couldn't find a RyProx release to download. Try --docker (it can build from source), or create a release first."
fi
ok "Method: $([ "$METHOD" = docker ] && echo Docker || echo 'system service') · version: ${VERSION:-latest source}"

# ---------- questions (first install only) ----------
PUBLIC_IP=""
if [ -z "$EXISTING" ]; then
  step "Setup"
  PUBLIC_IP=$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  if [ -n "$PUBLIC_IP" ]; then say "  This server's public IP address looks like ${B}${PUBLIC_IP}${N}."; fi

  normalize_domain() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's#^https\{0,1\}://##; s#/.*$##; s#\.$##'; }
  DOMAIN=$(normalize_domain "$DOMAIN")
  if [ -z "$DOMAIN" ]; then
    say "  People sign in to your private sites on one domain of RyProx's own, such as"
    say "  login.example.com. Create a DNS record for it. Leave empty to set it up later."
    while :; do
      ask DOMAIN "  Sign-in domain" ""
      DOMAIN=$(normalize_domain "$DOMAIN")
      if [ -z "$DOMAIN" ] || valid_domain "$DOMAIN"; then break; fi
      if [ "$YES" = 1 ] || [ -z "$TTY" ]; then die "invalid domain: $DOMAIN"; fi
      warn "That doesn't look like a domain name. Try again, or leave it empty."
    done
  fi
  if [ -n "$DOMAIN" ] && ! valid_domain "$DOMAIN"; then die "invalid domain: $DOMAIN"; fi
  DASHBOARD=$(normalize_domain "$DASHBOARD")
  if [ -n "$DASHBOARD" ] && ! valid_domain "$DASHBOARD"; then die "invalid domain: $DASHBOARD"; fi

  if [ -z "$EMAIL" ]; then
    if [ -n "$DOMAIN$DASHBOARD" ]; then
      say "  Let's Encrypt needs an email for certificate expiry warnings."
    else
      say "  For automatic HTTPS, enter an email for Let's Encrypt. Leave empty to set up HTTPS later."
    fi
    while :; do
      ask EMAIL "  Email" ""
      if { [ -z "$EMAIL" ] && [ -z "$DOMAIN$DASHBOARD" ]; } || valid_email "$EMAIL"; then break; fi
      if [ "$YES" = 1 ] || [ -z "$TTY" ]; then die "a valid --email is needed with a domain"; fi
      warn "Please enter a valid email address."
    done
  fi
  if [ -n "$EMAIL" ] && ! valid_email "$EMAIL"; then die "invalid email: $EMAIL"; fi
  if [ -n "$DOMAIN$DASHBOARD" ] && [ -z "$EMAIL" ]; then die "a domain needs an email for its HTTPS certificate"; fi

  if [ -n "$EMAIL" ] && [ -z "$STAGING" ]; then
    say "  Test certificates let you get everything working without hitting Let's Encrypt's limits."
    say "  Browsers will warn about them; switch to real ones in Settings when you're happy."
    if confirm "  Start with test certificates?" y; then STAGING=yes; else STAGING=no; fi
  fi

  # Ports 80 and 443 must be free.
  step "Checking this server"
  if command -v ss >/dev/null; then
    for p in 80 443; do
      if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then
        who=$(ss -ltnpH "sport = :$p" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n1)
        warn "Port $p is already used${who:+ by $who}. Stop it first, or RyProx won't be able to start."
      else
        ok "Port $p is free"
      fi
    done
  fi

  # DNS for the dashboard domain.
  if [ -n "$DOMAIN" ]; then
    resolved=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || true)
    if [ -z "$resolved" ]; then
      warn "$DOMAIN doesn't resolve yet. Add a DNS A record pointing it at ${PUBLIC_IP:-this server}."
    elif [ -n "$PUBLIC_IP" ] && [ "$resolved" != "$PUBLIC_IP" ]; then
      warn "$DOMAIN points at $resolved, but this server looks like $PUBLIC_IP. HTTPS will fail until DNS is right."
      warn "(If you use Cloudflare, set the record to DNS only / grey cloud.)"
    else
      ok "$DOMAIN points at this server"
    fi
  fi

  # Firewall.
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if confirm "  Allow ports 80 and 443 through the ufw firewall?" y; then
      run ufw allow 80/tcp >/dev/null && run ufw allow 443/tcp >/dev/null && ok "Firewall opened for 80 and 443"
    fi
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    if confirm "  Allow ports 80 and 443 through firewalld?" y; then
      run firewall-cmd --permanent --add-service=http --add-service=https >/dev/null
      run firewall-cmd --reload >/dev/null
      ok "Firewall opened for 80 and 443"
    fi
  fi

  step "Ready to install"
  say "  Method:     $([ "$METHOD" = docker ] && echo Docker || echo 'system service')"
  say "  Sign-in:    $([ -n "$DOMAIN" ] && echo "https://$DOMAIN" || echo 'set up later in Settings')"
  say "  Dashboard:  $([ -n "$DASHBOARD" ] && echo "https://$DASHBOARD" || echo 'this server only (SSH tunnel)')"
  say "  HTTPS:      $([ -n "$EMAIL" ] && { [ "$STAGING" = yes ] && echo "automatic (test certificates)" || echo automatic; } || echo 'off for now (turn on in Settings)')"
  confirm "  Install now?" y || die "cancelled; nothing was changed."
fi

INIT_ARGS=()
if [ -n "$EMAIL" ]; then
  INIT_ARGS+=(--acme-email "$EMAIL")
  if [ "$STAGING" = yes ]; then INIT_ARGS+=(--acme-staging); fi
fi
if [ -n "$DOMAIN" ]; then INIT_ARGS+=(--auth-domain "$DOMAIN"); fi
if [ -n "$DASHBOARD" ]; then INIT_ARGS+=(--admin-domain "$DASHBOARD"); fi

# ---------- install: Docker ----------
install_docker() {
  step "Installing with Docker"
  local img
  if [ -n "$VERSION" ] && run docker pull "$IMAGE:$VERSION" >/dev/null 2>&1; then
    img="$IMAGE:$VERSION"
    ok "Downloaded $img"
  else
    img="ryprox:local"
    say "  No published image found; building from the source code (takes a minute or two)."
    run docker build -t "$img" "https://github.com/$REPO.git#${VERSION:-main}"
    ok "Built $img"
  fi

  run docker volume create "$VOLUME" >/dev/null
  if [ -z "$EXISTING" ] && [ ${#INIT_ARGS[@]} -gt 0 ]; then
    run docker run --rm -v "$VOLUME:/data" "$img" init --data /data "${INIT_ARGS[@]}"
  fi

  if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
    run docker rm -f "$CONTAINER" >/dev/null
  fi
  run docker run -d --name "$CONTAINER" --restart unless-stopped \
    -p 80:80 -p 443:443 -p "127.0.0.1:$ADMIN_PORT:8081" \
    -v "$VOLUME:/data" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    "$img" >/dev/null
  ok "RyProx container started"
}

# ---------- install: system service ----------
install_native() {
  step "Installing as a system service"
  local tmp name url
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  name="ryprox_${VERSION}_linux_${ARCH}"
  url="https://github.com/$REPO/releases/download/$VERSION"
  run curl -fsSL --max-time 120 -o "$tmp/$name.tar.gz" "$url/$name.tar.gz"
  run curl -fsSL --max-time 30 -o "$tmp/sha256sums.txt" "$url/sha256sums.txt"
  if [ "$DRY" != 1 ]; then
    (cd "$tmp" && grep " $name.tar.gz\$" sha256sums.txt | sha256sum -c --quiet -) \
      || die "the download's checksum doesn't match. Nothing was installed."
    tar -C "$tmp" -xzf "$tmp/$name.tar.gz"
  fi
  ok "Downloaded RyProx $VERSION and checked its checksum"

  if ! id ryprox >/dev/null 2>&1; then
    run useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin ryprox
    ok "Created the ryprox system user"
  fi
  run install -d -m 0700 -o ryprox -g ryprox "$DATA"

  if [ -n "$EXISTING" ]; then run systemctl stop ryprox; fi
  run install -m 0755 "$tmp/$name/ryprox" "$BIN"
  ok "Installed $BIN"

  if [ -z "$EXISTING" ] && [ ${#INIT_ARGS[@]} -gt 0 ]; then
    if command -v runuser >/dev/null; then
      run runuser -u ryprox -- "$BIN" init --data "$DATA" "${INIT_ARGS[@]}"
    else
      run su -s /bin/sh ryprox -c "$(printf '%q ' "$BIN" init --data "$DATA" "${INIT_ARGS[@]}")"
    fi
  fi

  if [ "$DRY" = 1 ]; then
    say "  [dry-run] write $UNIT"
  else
    cat > "$UNIT" <<EOF
[Unit]
Description=RyProx reverse proxy
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN serve
Environment=RYPROX_DATA=$DATA
Environment=RYPROX_ADMIN=127.0.0.1:$ADMIN_PORT
Restart=on-failure
RestartSec=3
User=ryprox
Group=ryprox
StateDirectory=ryprox
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  fi
  run systemctl daemon-reload
  run systemctl enable --now ryprox >/dev/null 2>&1
  ok "RyProx service started and set to start on boot"
}

if [ "$METHOD" = docker ]; then install_docker; else install_native; fi

# ---------- wait until it's up ----------
step "Starting"
if [ "$DRY" = 1 ]; then
  ok "[dry-run] would wait for RyProx to answer on 127.0.0.1:$ADMIN_PORT"
else
  up=0
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 2 --noproxy '*' "http://127.0.0.1:$ADMIN_PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
    sleep 1
  done
  if [ "$up" != 1 ]; then
    warn "RyProx didn't answer within 30 seconds. Its recent logs:"
    if [ "$METHOD" = docker ]; then docker logs --tail 30 "$CONTAINER" 2>&1 | sed 's/^/    /'
    else journalctl -u ryprox -n 30 --no-pager 2>&1 | sed 's/^/    /'; fi
    die "RyProx failed to start (see above)."
  fi
  ok "RyProx is running"
fi

# ---------- finish ----------
CODE=""
if [ "$DRY" != 1 ]; then
  if [ "$METHOD" = docker ]; then logs=$(docker logs "$CONTAINER" 2>&1 || true)
  else logs=$(journalctl -u ryprox -n 200 --no-pager 2>/dev/null || true); fi
  CODE=$(printf '%s\n' "$logs" | sed -n 's/.*setup code: *\([A-Z0-9-]*\).*/\1/p' | tail -n1)
fi

printf '\n%s%s%s\n' "$G" "────────────────────────────────────────────────────────" "$N"
if [ -n "$EXISTING" ]; then
  printf '  %sRyProx is updated.%s Your routes and settings are unchanged.\n' "$B" "$N"
else
  printf '  %sRyProx is installed.%s\n\n' "$B" "$N"
  if [ -n "$CODE" ]; then
    printf '  Your setup code:  %s%s%s\n' "$B" "$CODE" "$N"
  else
    say "  Find your setup code in the logs:"
    if [ "$METHOD" = docker ]; then say "    docker logs $CONTAINER"; else say "    journalctl -u ryprox"; fi
  fi
  say ""
  say "  Open the dashboard and enter the code to create your admin account:"
  if [ -n "$DASHBOARD" ]; then
    say "    https://$DASHBOARD"
    say "    ${D}(the certificate can take a minute; until then, use the tunnel below)${N}"
  fi
  say "    From your computer:  ssh -L $ADMIN_PORT:127.0.0.1:$ADMIN_PORT you@${PUBLIC_IP:-this-server}"
  say "    then visit           http://localhost:$ADMIN_PORT"
  say ""
  say "  More information: https://github.com/$REPO"
fi
printf '%s%s%s\n\n' "$G" "────────────────────────────────────────────────────────" "$N"
