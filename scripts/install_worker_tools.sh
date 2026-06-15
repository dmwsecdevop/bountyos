#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run using sudo: sudo bash scripts/install_worker_tools.sh" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "== Installing system packages =="

apt-get update

apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  wget \
  git \
  unzip \
  zip \
  jq \
  make \
  gcc \
  g++ \
  libc6-dev \
  libpcap-dev \
  pkg-config \
  python3 \
  python3-pip \
  python3-venv \
  pipx \
  nmap \
  masscan \
  sqlmap \
  whatweb \
  nikto \
  gobuster \
  dnsutils \
  whois \
  openssl \
  netcat-openbsd

# Optional Debian tools: failure of one package will not stop everything.
for package in amass dnsrecon dnsenum fierce wafw00f; do
  apt-get install -y --no-install-recommends "$package" ||
    echo "WARNING: optional package unavailable: $package"
done

echo "== Installing Go 1.25.11 =="

GO_VERSION="1.25.11"
ARCH="$(dpkg --print-architecture)"

case "$ARCH" in
  amd64) GO_ARCH="amd64" ;;
  arm64) GO_ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

GO_ARCHIVE="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"

curl -fL \
  "https://go.dev/dl/${GO_ARCHIVE}" \
  -o "/tmp/${GO_ARCHIVE}"

rm -rf /usr/local/go
tar -C /usr/local -xzf "/tmp/${GO_ARCHIVE}"
rm -f "/tmp/${GO_ARCHIVE}"

cat > /etc/profile.d/bountyos-go.sh <<'EOF'
export PATH=/usr/local/go/bin:/usr/local/bin:$PATH
export GOPATH=${GOPATH:-/opt/bountyos-go}
export GOTOOLCHAIN=auto
EOF

export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"
export GOPATH="/opt/bountyos-go"
export GOTOOLCHAIN="auto"

mkdir -p "$GOPATH"

go version

install_go_tool() {
  local name="$1"
  local package="$2"

  echo
  echo "Installing $name from $package"

  if GOBIN=/usr/local/bin go install "$package"; then
    echo "OK: $name installed"
  else
    echo "WARNING: $name installation failed" >&2
  fi
}

echo "== Installing ProjectDiscovery tools =="

install_go_tool subfinder \
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

install_go_tool httpx \
  github.com/projectdiscovery/httpx/cmd/httpx@latest

install_go_tool nuclei \
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

install_go_tool naabu \
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

install_go_tool dnsx \
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest

CGO_ENABLED=1 install_go_tool katana \
  github.com/projectdiscovery/katana/cmd/katana@latest

echo "== Installing additional recon tools =="

install_go_tool ffuf \
  github.com/ffuf/ffuf/v2@v2.1.0

install_go_tool gau \
  github.com/lc/gau/v2/cmd/gau@v2.2.4

install_go_tool waybackurls \
  github.com/tomnomnom/waybackurls@v0.1.0

install_go_tool assetfinder \
  github.com/tomnomnom/assetfinder@v0.1.1

install_go_tool anew \
  github.com/tomnomnom/anew@latest

install_go_tool qsreplace \
  github.com/tomnomnom/qsreplace@latest

install_go_tool unfurl \
  github.com/tomnomnom/unfurl@latest

install_go_tool hakrawler \
  github.com/hakluke/hakrawler@latest

install_go_tool gospider \
  github.com/jaeles-project/gospider@latest

echo "== Installing Python security utilities =="

python3 -m venv /opt/bountyos-tools-venv

/opt/bountyos-tools-venv/bin/pip install \
  --upgrade pip setuptools wheel

for package in shodan arjun uro; do
  /opt/bountyos-tools-venv/bin/pip install "$package" ||
    echo "WARNING: Python package failed: $package"
done

for executable in shodan arjun uro; do
  if [[ -x "/opt/bountyos-tools-venv/bin/${executable}" ]]; then
    ln -sf \
      "/opt/bountyos-tools-venv/bin/${executable}" \
      "/usr/local/bin/${executable}"
  fi
done

echo "== Updating Nuclei templates =="

if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates || true
fi

echo "== Creating tool inventory =="

TOOLS=(
  subfinder httpx nuclei naabu dnsx katana
  ffuf gau waybackurls assetfinder anew qsreplace unfurl
  hakrawler gospider
  nmap masscan sqlmap whatweb nikto gobuster
  amass dnsrecon dnsenum fierce wafw00f
  shodan arjun uro
)

INVENTORY="/var/lib/bountyos-tool-inventory.txt"

mkdir -p "$(dirname "$INVENTORY")"
: > "$INVENTORY"

printf "\n%-18s %-9s %s\n" "TOOL" "STATUS" "PATH"
printf "%-18s %-9s %s\n" "------------------" "---------" "----"

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    tool_path="$(command -v "$tool")"

    printf "%-18s %-9s %s\n" "$tool" "OK" "$tool_path"
    printf "%s|OK|%s\n" "$tool" "$tool_path" >> "$INVENTORY"
  else
    printf "%-18s %-9s %s\n" "$tool" "MISSING" "-"
    printf "%s|MISSING|\n" "$tool" >> "$INVENTORY"
  fi
done

echo
echo "Inventory: $INVENTORY"
echo "Worker installation completed."
