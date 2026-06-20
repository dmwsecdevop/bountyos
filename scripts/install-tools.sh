#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash scripts/install-tools.sh" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
export GOPATH="${GOPATH:-/opt/bountyos-go}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

INSTALLED=()
SKIPPED=()
MISSING=()
FAILED=()

have() { command -v "$1" >/dev/null 2>&1; }
remember() {
  local tool="$1"
  if have "$tool"; then INSTALLED+=("$tool:$(command -v "$tool")"); else MISSING+=("$tool"); fi
}
apt_install_optional() {
  local tool="$1" package="${2:-$1}"
  if have "$tool"; then SKIPPED+=("$tool"); return 0; fi
  echo "== apt install $package =="
  if apt-get install -y --no-install-recommends "$package"; then
    remember "$tool"
  else
    echo "WARNING: apt package failed: $package" >&2
    FAILED+=("$tool")
  fi
}
install_go() {
  local tool="$1" module="$2"
  if have "$tool"; then SKIPPED+=("$tool"); return 0; fi
  if ! have go; then FAILED+=("$tool:no-go"); return 0; fi
  echo "== go install $tool =="
  if GOBIN=/usr/local/bin go install "$module"; then
    remember "$tool"
  else
    echo "WARNING: go install failed: $tool" >&2
    FAILED+=("$tool")
  fi
}
install_python_tool() {
  local tool="$1" package="${2:-$1}"
  if have "$tool"; then SKIPPED+=("$tool"); return 0; fi
  echo "== pipx install $package =="
  if pipx install --global "$package"; then
    remember "$tool"
  else
    echo "WARNING: pipx install failed: $package" >&2
    FAILED+=("$tool")
  fi
}
install_rustscan() {
  if have rustscan; then SKIPPED+=("rustscan"); return 0; fi
  local arch deb url
  arch="$(dpkg --print-architecture)"
  case "$arch" in
    amd64) deb="rustscan_2.4.1_amd64.deb" ;;
    arm64) deb="rustscan_2.4.1_arm64.deb" ;;
    *) echo "WARNING: unsupported arch for rustscan: $arch" >&2; FAILED+=("rustscan"); return 0 ;;
  esac
  url="https://github.com/bee-san/RustScan/releases/download/2.4.1/${deb}"
  echo "== install rustscan =="
  if curl -fL "$url" -o "/tmp/${deb}" && apt-get install -y "/tmp/${deb}"; then
    rm -f "/tmp/${deb}"; remember rustscan
  else
    rm -f "/tmp/${deb}"; echo "WARNING: rustscan install failed" >&2; FAILED+=("rustscan")
  fi
}

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl wget git unzip zip jq make gcc g++ libc6-dev libpcap-dev pkg-config python3 python3-pip python3-venv pipx dnsutils whois openssl netcat-openbsd

for spec in \
  "jq:jq" "curl:curl" "wget:wget" "git:git" "python3:python3" "nmap:nmap" "masscan:masscan" \
  "sqlmap:sqlmap" "nikto:nikto" "whatweb:whatweb" "wafw00f:wafw00f" "gobuster:gobuster" \
  "feroxbuster:feroxbuster" "amass:amass"; do
  IFS=: read -r tool package <<<"$spec"
  apt_install_optional "$tool" "$package"
done

if ! have go; then
  GO_VERSION="1.25.11"
  case "$(dpkg --print-architecture)" in amd64) GO_ARCH=amd64 ;; arm64) GO_ARCH=arm64 ;; *) GO_ARCH= ;; esac
  if [[ -n "${GO_ARCH}" ]]; then
    archive="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    echo "== install Go ${GO_VERSION} =="
    if curl -fL "https://go.dev/dl/${archive}" -o "/tmp/${archive}"; then
      rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${archive}" && rm -f "/tmp/${archive}"
      cat >/etc/profile.d/bountyos-go.sh <<'GOEOF'
export PATH=/usr/local/go/bin:/usr/local/bin:$PATH
export GOPATH=${GOPATH:-/opt/bountyos-go}
export GOTOOLCHAIN=auto
GOEOF
    else
      echo "WARNING: Go download failed" >&2
    fi
  fi
fi
mkdir -p "$GOPATH"

install_go subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
install_go katana github.com/projectdiscovery/katana/cmd/katana@latest
install_go dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest
install_go assetfinder github.com/tomnomnom/assetfinder@latest
install_go gau github.com/lc/gau/v2/cmd/gau@latest
install_go waybackurls github.com/tomnomnom/waybackurls@latest
install_go ffuf github.com/ffuf/ffuf/v2@latest
install_go dalfox github.com/hahwul/dalfox/v2@latest

install_python_tool dirsearch dirsearch
install_rustscan

if have nuclei; then
  echo "== update nuclei templates =="
  nuclei -update-templates || echo "WARNING: nuclei template update failed" >&2
fi

REQUIRED=(subfinder httpx nuclei naabu katana dnsx amass assetfinder gau waybackurls ffuf feroxbuster gobuster dirsearch sqlmap dalfox nmap rustscan masscan nikto whatweb wafw00f jq curl wget git python3 go)
MISSING=()
for tool in "${REQUIRED[@]}"; do remember "$tool"; done

printf '\n%-18s %-9s %s\n' TOOL STATUS PATH
printf '%-18s %-9s %s\n' ------------------ --------- ----
for tool in "${REQUIRED[@]}" nuclei-templates; do
  if [[ "$tool" == "nuclei-templates" ]]; then
    path="${HOME}/nuclei-templates"
    [[ -d "$path" || -d /root/nuclei-templates ]] && printf '%-18s %-9s %s\n' "$tool" OK "${path}" || printf '%-18s %-9s %s\n' "$tool" MISSING -
  elif have "$tool"; then
    printf '%-18s %-9s %s\n' "$tool" OK "$(command -v "$tool")"
  else
    printf '%-18s %-9s %s\n' "$tool" MISSING -
  fi
done

if ((${#FAILED[@]})); then
  printf '\nWARNING: optional installs failed: %s\n' "${FAILED[*]}" >&2
fi
