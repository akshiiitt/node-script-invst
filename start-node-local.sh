#!/usr/bin/env bash
set -Eeou pipefail

# InvestNet dVPN Node management script
# - Provides commands: init, start, stop, restart, status, uninstall-wireguard, uninstall-service
# - Writes a systemd unit to run the node and syncs WireGuard settings into config.toml
# - Safe by default: strict bash mode, clear logging, and minimal side effects

NODE_DIR="${HOME}/.investnet-dvpnx"
BINARY="${BINARY:-investnet-dvpnx}"  # Default binary name; override by setting $BINARY
REPO_URL="https://github.com/akshiiitt/node-local-binary"             # GitHub Repo URL for auto-download
API_PORT=18133

# Lightweight helpers
log() { echo "[INFO] $*"; }
err() { echo "[ERROR] $*" >&2; }
require() { command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }; }

# Auto-download binary from GitHub Releases

download_binary() {
  if command -v "${BINARY}" &> /dev/null || [[ -x "./${BINARY}" ]]; then
    if [[ -x "./${BINARY}" ]] && ! command -v "${BINARY}" &> /dev/null; then
      BINARY="./${BINARY}"
    fi
    return
  fi

  if [[ -z "${REPO_URL}" ]]; then
    err "Binary '${BINARY}' not found and REPO_URL is not set."
    echo "Please set your GitHub Repo URL, for example:"
    echo "export REPO_URL=\"https://github.com/Antier-Dev/investnet-dvpnx\""
    exit 1
  fi

  log "Binary '${BINARY}' not found. Attempting auto-download from ${REPO_URL}..."
  
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)

  case "${arch}" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) err "Unsupported architecture: ${arch}"; exit 1 ;;
  esac

  # Expected asset name format: binary-os-arch (e.g., investnet-dvpnx-linux-amd64)
  local asset_name="${BINARY}-${os}-${arch}"
  local repo_path=$(echo "${REPO_URL}" | sed -E 's|https://github.com/||' | sed 's|/$||')
  local api_url="https://api.github.com/repos/${repo_path}/releases/latest"
  
  log "Fetching latest release info from GitHub API..."
  local download_url=$(curl -sL "${api_url}" | jq -r ".assets[] | select(.name == \"${asset_name}\") | .browser_download_url" || true)

  if [[ -z "${download_url}" || "${download_url}" == "null" ]]; then
    err "Could not find a matching binary for ${os}-${arch} in the latest release."
    err "Make sure you uploaded '${asset_name}' to your GitHub Release."
    exit 1
  fi

  log "Downloading ${asset_name}..."
  curl -L "${download_url}" -o "${BINARY}"
  chmod +x "${BINARY}"
  BINARY="./${BINARY}"
  log "Successfully downloaded and prepared ${BINARY}"
}

CHAIN_RPC="${CHAIN_RPC:-http://localhost:26657}"
CHAIN_ID="${CHAIN_ID:-investnet_7032-1}"
KEYRING_BACKEND="test"
KEYRING_NAME="investnet"
WG_CONF="/etc/wireguard/wg0.conf"
SYSTEMD_UNIT="/etc/systemd/system/investnet-dvpn-node.service"
NODE_TYPE="wireguard"
CONFIG_TOML="${NODE_DIR}/config.toml"
DENOM="invst"
NODE_INTERVAL_SESSION_USAGE_SYNC_WITH_BLOCKCHAIN="540s"
NODE_INTERVAL_SESSION_VALIDATE="60s"
NODE_INTERVAL_STATUS_UPDATE="240s"
# Detect public IP(s); prompt user if auto-detect fails
resolve_public_ip() {
  local ipv4 ipv6
  ipv4=$(curl -4fsSL --max-time 5 https://ifconfig.me 2>/dev/null || curl -4fsSL --max-time 5 https://icanhazip.com 2>/dev/null || true)
  ipv6=$(curl -6fsSL --max-time 5 https://ifconfig.me 2>/dev/null || curl -6fsSL --max-time 5 https://icanhazip.com 2>/dev/null || true)
  
  ipv4=$(echo "$ipv4" | tr -d '[:space:]')
  ipv6=$(echo "$ipv6" | tr -d '[:space:]')

  if [[ -z "${ipv4}" && -z "${ipv6}" ]]; then
    echo "⚠ Could not auto-detect public IPv4 or IPv6."
    read -rp "Enter your public IP(s) (comma-separated for both): " PUBLIC_IP
    PUBLIC_IP=$(echo "$PUBLIC_IP" | tr -d '[:space:]')
    if [[ -z "${PUBLIC_IP}" ]]; then
      err "Public IP is required. Cannot continue."
      exit 1
    fi
  else
    # Combine detected IPs
    if [[ -n "${ipv4}" && -n "${ipv6}" ]]; then
      PUBLIC_IP="${ipv4},${ipv6}"
    elif [[ -n "${ipv4}" ]]; then
      PUBLIC_IP="${ipv4}"
    else
      PUBLIC_IP="${ipv6}"
    fi
  fi
}
# Check if an IP string is IPv6 (contains colons)
is_ipv6() { [[ "$1" == *:* ]]; }


# Sync wireguard settings from wg0.conf into config.toml
update_wireguard_config_from_wg() {
  # Read core fields from /etc/wireguard/wg0.conf (if present)
  if sudo test -f "$WG_CONF"; then
  WG_ADDRESS=$(sudo grep -m1 '^Address' "$WG_CONF" | sed -E 's/.*[:=][[:space:]]*//')
  WG_LISTENPORT=$(sudo grep -m1 '^ListenPort' "$WG_CONF" | sed -E 's/.*[:=][[:space:]]*//')
  WG_PRIVATEKEY=$(sudo grep -m1 '^PrivateKey' "$WG_CONF" | awk -F '=' '{print $2}')
  PRIVATE_KEY=$(echo "$WG_PRIVATEKEY" | xargs)
  # Ensure WireGuard private key ends with '=' padding when needed
  if [[ "$PRIVATE_KEY" != *= ]]; then
    PRIVATE_KEY="${PRIVATE_KEY}="
  fi
    # Split WG_ADDRESS into IPv4 and IPv6 parts (Address may be "10.0.0.1/24,fd00::1/64")
    WG_IPV4_ADDR=""
    WG_IPV6_ADDR=""
    IFS=',' read -ra ADDR_PARTS <<< "$WG_ADDRESS"
    for part in "${ADDR_PARTS[@]}"; do
      part=$(echo "$part" | xargs)  # trim whitespace
      if is_ipv6 "$part"; then
        WG_IPV6_ADDR="$part"
      else
        WG_IPV4_ADDR="$part"
      fi
    done

    echo "WireGuard Config:"
    echo "- IPv4 Address: ${WG_IPV4_ADDR:-<not set>}"
    echo "- IPv6 Address: ${WG_IPV6_ADDR:-<not set>}"
    echo "- ListenPort: $WG_LISTENPORT"
    echo "- PrivateKey: $PRIVATE_KEY"
  else
    echo "WireGuard config not found at $WG_CONF"
  fi

  # Update ~/.investnet-dvpnx/config.toml [wireguard] section with values from wg0.conf
  if [[ -f "$CONFIG_TOML" ]]; then
    # Only update when all required fields are available
    if [[ (-n "$WG_IPV4_ADDR" || -n "$WG_IPV6_ADDR") && -n "$WG_LISTENPORT" && -n "$WG_PRIVATEKEY" ]]; then
      echo "Updating $CONFIG_TOML [wireguard] ipv4_addr, ipv6_addr, port, private_key"
      # Create a timestamped backup before in-place edits
      cp "$CONFIG_TOML" "${CONFIG_TOML}.bak.$(date +%s)"
      # Replace only inside [wireguard] section using a bounded sed range
      sed -i -E '/^\[wireguard\]/,/^\[/ {
        s|^ipv4_addr = .*|ipv4_addr = '"'"${WG_IPV4_ADDR//&/\\&}"'"'|
        s|^ipv6_addr = .*|ipv6_addr = '"'"${WG_IPV6_ADDR//&/\\&}"'"'|
        s|^port = .*|port = '"'"${WG_LISTENPORT//&/\\&}"'"'|
        s|^private_key = .*|private_key = '"'"${PRIVATE_KEY//&/\\&}"'"'|
      }' "$CONFIG_TOML"
    else
      echo "WireGuard values missing; skipping config.toml update"
    fi
  else
    echo "Config file not found at $CONFIG_TOML"
  fi
}

# Write or update the systemd unit for the node
write_systemd_unit() {
  # Get absolute path - try command -v first, then check if it's a file
  BIN_PATH=$(command -v "${BINARY}" 2>/dev/null || true)
  if [[ -z "$BIN_PATH" && -x "${BINARY}" ]]; then
    BIN_PATH="${BINARY}"
  fi
  if [[ -z "$BIN_PATH" || ! -x "$BIN_PATH" ]]; then
    err "Binary ${BINARY} not found or not executable"; exit 1
  fi
  # Ensure absolute path for systemd (relative paths don't work)
  BIN_PATH=$(realpath "$BIN_PATH")
  # Emit a minimal, resilient unit file to run the node as root (needed for WG interface management)
  sudo bash -c "cat > ${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=InvestNet dVPN Node
Wants=network-online.target
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=${BIN_PATH} start --home ${NODE_DIR} --keyring.backend ${KEYRING_BACKEND}
Restart=always
RestartSec=5
LimitNOFILE=65536
Environment=DAEMON_NAME=${BINARY}
Environment=DAEMON_HOME=${NODE_DIR}
Environment=DAEMON_ALLOW_DOWNLOAD_BINARIES=false
Environment=DAEMON_RESTART_AFTER_UPGRADE=true
Environment=DAEMON_LOG_BUFFER_SIZE=512
Environment=UNSAFE_SKIP_BACKUP=false

[Install]
WantedBy=multi-user.target
EOF
}

# Human-friendly CLI help
function cmd_help {
  echo "Usage: ${0} [COMMAND]"
  echo ""
  echo "Commands:"
  echo "  init       Initialize configuration and keys"
  echo "  start      Configure and start the node via systemd"
  echo "  stop       Stop the systemd service"
  echo "  restart    Restart the systemd service"
  echo "  status     Show service status and recent logs"
  echo "  uninstall-wireguard  Bring down interfaces, purge packages, remove /etc/wireguard"
  echo "  uninstall-service    Stop/disable service, remove unit file and node data"
  echo "  help       Print this help message"
  echo ""
  echo "Environment Variables:"
  echo "  CHAIN_RPC  - Chain RPC endpoint (default: http://localhost:26657)"
  echo "  CHAIN_ID   - Chain ID (default: investnet_7032-1)"
  echo "  BINARY     - Binary name (default: investnet-dvpnx)"
  echo "  REPO_URL   - GitHub Repo URL for auto-download"
}


# Initialize node: ensure binary, create config, and add keys
function cmd_init {
  download_binary
  resolve_public_ip
  # --- WireGuard prerequisite check ---
  if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
    err "WireGuard is not installed. Please install it before initializing the node."
    echo "On Ubuntu: sudo apt install wireguard wireguard-tools"
    exit 1
  fi

  # Prepare node home and select a moniker
  mkdir -p "${NODE_DIR}"
  MONIKER="investnet-node-$(openssl rand -hex 4)"
  
  read -p "Enter the Node name (default: ${MONIKER}): " NODE_NAME
  if [[ -n "${NODE_NAME}" ]]; then
    MONIKER="${NODE_NAME}"
  fi

  echo "Detected public IP: ${PUBLIC_IP}"
  echo "Generated moniker: ${MONIKER}"
  echo "Selected API port: ${API_PORT}"
  echo "Chain RPC: ${CHAIN_RPC}"
  echo "Chain ID: ${CHAIN_ID}"
  echo ""

    # Price format for InvestNet: denom:base_value,quote_value
    GIGABYTE_PRICES="${DENOM}:20.0,20000000000000000000"

    while true; do
        read -p "Enter hourly price (default: 1): " HOURLY_INPUT
        HOURLY_INPUT="${HOURLY_INPUT:-1}"
        if ! [[ "$HOURLY_INPUT" =~ ^[0-9]+$ ]]; then
          echo "[ERROR] Invalid input: only whole numbers allowed (no decimals, no letters)."
          continue
        fi
        if [[ ${#HOURLY_INPUT} -gt 6 ]]; then
            echo "[ERROR] Value too large. Maximum 6 digits allowed (max: 999999)."
          continue
        fi
        break
      done
      HOURLY_QUOTE=$(python3 -c "print(${HOURLY_INPUT} * 10**18)")
    HOURLY_PRICES="${DENOM}:${HOURLY_INPUT},${HOURLY_QUOTE}"

    echo "Initializing config..."
    "${BINARY}" init \
      --force \
      --home "${NODE_DIR}" \
      --node.moniker "${MONIKER}" \
      --node.api-port "${API_PORT}" \
      --node.remote-addrs "${PUBLIC_IP}" \
    --node.gigabyte-prices "${GIGABYTE_PRICES}" \
    --node.hourly-prices "${HOURLY_PRICES}" \
    --node.service-type "${NODE_TYPE}" \
    --rpc.addrs "${CHAIN_RPC}" \
    --rpc.chain-id "${CHAIN_ID}" \
    --keyring.backend "${KEYRING_BACKEND}" \
    --keyring.name "${KEYRING_NAME}" \
    --node.interval-session-usage-sync-with-blockchain "${NODE_INTERVAL_SESSION_USAGE_SYNC_WITH_BLOCKCHAIN}" \
    --node.interval-session-validate "${NODE_INTERVAL_SESSION_VALIDATE}" \
    --node.interval-status-update "${NODE_INTERVAL_STATUS_UPDATE}" \
    --tx.gas-prices  "1000000000invst" 

  echo "Initializing keys..."
  read -p "Enter the account name (default: main): " ACCOUNT_NAME
  if [[ -z "${ACCOUNT_NAME}" ]]; then
    ACCOUNT_NAME="main"
  fi
  "${BINARY}" keys add "${ACCOUNT_NAME}" \
    --home "${NODE_DIR}" \
    --keyring.backend "${KEYRING_BACKEND}" \
    --keyring.name "${KEYRING_NAME}"

  # Keep CLI transactions consistent by setting from_name in config.toml
  if [[ -f "${CONFIG_TOML}" ]]; then
    # Use sed to update the from_name field
    if sed -i "s/^from_name = .*/from_name = \"${ACCOUNT_NAME}\"/" "${CONFIG_TOML}"; then
      echo "Updated from_name to '${ACCOUNT_NAME}' in ${CONFIG_TOML}"
    else
      echo "Warning: Failed to update from_name in ${CONFIG_TOML}"
    fi
  fi

  echo "====================================================================================="
  echo "IMPORTANT: Save the mnemonics and key address to a safe place!"
  echo "Make sure the key has balance before running START command."
  echo ""
  echo "To fund the key on local testnet:"
  echo "  investnetd tx bank send dev0 <YOUR_KEY_ADDRESS> 1000000000${DENOM} \\"
  echo "    --chain-id ${CHAIN_ID} --keyring-backend test -y"
  echo "====================================================================================="
}


# Configure and start the node via systemd, then report basic health info
function cmd_start {
    download_binary
    resolve_public_ip
    
    if [[ ! -f "${NODE_DIR}/config.toml" ]]; then
      err "Config file not found at ${NODE_DIR}/config.toml"; exit 1
    fi

    # 1. Clean up any existing stale interface ONCE before starting
    sudo wg-quick down wg0 2>/dev/null || true
    sudo ip link delete wg0 2>/dev/null || true

    # 2. Read dynamic settings from config.toml; fail fast if missing
    API_PORT_CFG=$(grep '^api_port = ' "${NODE_DIR}/config.toml" | cut -d'"' -f2 || true)
    NODE_TYPE_CFG=$(grep '^service_type = ' "${NODE_DIR}/config.toml" | cut -d'"' -f2 || true)
    if [[ -z "${API_PORT_CFG}" || -z "${NODE_TYPE_CFG}" ]]; then
      err "Could not read required configuration. Check config.toml format."; exit 1
    fi

    # Remove any existing https:// from the IP address
    CLEAN_IP=${PUBLIC_IP#https://}
    CLEAN_IP=${CLEAN_IP#http://}
    echo "Clean IP: ${CLEAN_IP}"
    
    echo "Starting node with command:"
    echo "${BINARY} start --home ${NODE_DIR} --keyring.backend ${KEYRING_BACKEND}"

    # 3. Ensure an up-to-date systemd unit and start it
    write_systemd_unit
    sudo systemctl daemon-reload
    sudo systemctl enable investnet-dvpn-node.service 
    sudo systemctl start investnet-dvpn-node.service 

    log "Waiting 30 seconds for binary to initialize WireGuard..."
    sleep 30

    # Best-effort fetch of node address from local API
    local check_ip
    IFS=',' read -ra IPS <<< "$PUBLIC_IP"
    check_ip="${IPS[0]}"
    for ip in "${IPS[@]}"; do
      if ! is_ipv6 "$ip"; then
        check_ip="$ip"
        break
      fi
    done

    if [[ -n "$check_ip" ]]; then
      # Wrap IPv6 in brackets for URL
      if is_ipv6 "$check_ip"; then
        API_HOST="[${check_ip}]"
      else
        API_HOST="$check_ip"
      fi
      NODE_ADDR=$(curl -sk "https://$API_HOST:$API_PORT_CFG" | jq -r '.result.addr' || true)
      if [[ -n "$NODE_ADDR" && "$NODE_ADDR" != "null" ]]; then
        log "Node address: $NODE_ADDR"
      else
        log "Node API reachable but address not yet available"
      fi
    fi
}

# Show service status and the most recent logs
function cmd_status {
  sudo systemctl status investnet-dvpn-node.service --no-pager | cat || true
  echo "--- Recent logs ---"
  sudo journalctl -u investnet-dvpn-node.service -n 50 --no-pager | cat || true
}

# Stop the systemd service (no error if not running)
function cmd_stop {
  sudo systemctl stop investnet-dvpn-node.service || true
}

# Restart the systemd service
function cmd_restart {
  sudo systemctl restart investnet-dvpn-node.service || true
}

# Uninstall dvpn-node systemd service and node data
function cmd_uninstall_service {
  echo "[INFO] Uninstalling investnet-dvpn-node systemd service and node data..."

  # Stop and disable the service if it exists
  sudo systemctl stop investnet-dvpn-node.service 2>/dev/null || true
  sudo systemctl disable investnet-dvpn-node.service 2>/dev/null || true

  # Remove unit file if present and reload daemon
  if [[ -f "${SYSTEMD_UNIT}" ]]; then
    sudo rm -f "${SYSTEMD_UNIT}" || true
    sudo systemctl daemon-reload || true
  else
    # Still reload in case it existed previously
    sudo systemctl daemon-reload || true
  fi

  # Remove node data directory
  if [[ -n "${NODE_DIR}" && -d "${NODE_DIR}" ]]; then
    sudo rm -rf "${NODE_DIR}" || true
  fi

  echo "[INFO] investnet-dvpn-node service and data removed."
}

# Uninstall WireGuard and thoroughly clean configuration, DNS, and firewall
function cmd_uninstall_wireguard {
  echo "[INFO] Uninstalling WireGuard and cleaning up..."

  # Bring down configured interfaces (runs PostDown rules if present)
  if command -v wg-quick >/dev/null 2>&1; then
    if [[ -n "${WG_CONF}" && -f "${WG_CONF}" ]]; then
      iface=$(basename "${WG_CONF}" .conf)
      sudo wg-quick down "$iface" || true
    fi
    for conf in /etc/wireguard/*.conf; do
      [[ -e "$conf" ]] || break
      iface=$(basename "$conf" .conf)
      sudo wg-quick down "$iface" || true
    done
  fi

  # Revert DNS for wg interfaces
  if command -v resolvectl >/dev/null 2>&1; then
    sudo resolvectl revert wg0 2>/dev/null || true
  fi
  if command -v resolvconf >/dev/null 2>&1; then
    sudo resolvconf -d wg0.inet 2>/dev/null || true
  fi

  # Delete lingering wg0 link if still present
  ip link show wg0 >/dev/null 2>&1 && sudo ip link del wg0 || true

  # Determine current primary egress interface for cleanup
  CLEAN_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
  [[ -z "$CLEAN_IFACE" ]] && CLEAN_IFACE=$(ip route | awk '/^default/ {print $5; exit}')

  # Remove iptables/ip6tables rules
  sudo iptables -D INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -i wg0 -o ${CLEAN_IFACE} -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -i ${CLEAN_IFACE} -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  sudo iptables -t nat -D POSTROUTING -o ${CLEAN_IFACE} -j MASQUERADE 2>/dev/null || true
  sudo ip6tables -D FORWARD -i wg0 -o ${CLEAN_IFACE} -j ACCEPT 2>/dev/null || true
  sudo ip6tables -D FORWARD -i ${CLEAN_IFACE} -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  sudo ip6tables -t nat -D POSTROUTING -o ${CLEAN_IFACE} -j MASQUERADE 2>/dev/null || true

  # nftables cleanup
  sudo nft delete rule inet wg-nat POSTROUTING oifname "${CLEAN_IFACE}" masquerade 2>/dev/null || true
  sudo nft list chains inet wg-nat >/dev/null 2>&1 && sudo nft flush chain inet wg-nat POSTROUTING 2>/dev/null || true
  sudo nft list tables inet | grep -q wg-nat && sudo nft delete table inet wg-nat 2>/dev/null || true

  # Stop/disable wg-quick unit if present
  sudo systemctl stop wg-quick@wg0 2>/dev/null || true
  sudo systemctl disable wg-quick@wg0 2>/dev/null || true

  # Close firewall port for WireGuard
  WG_PORT_CLEAN=""
  if [[ -f "/etc/wireguard/wg0.conf" ]]; then
    WG_PORT_CLEAN=$(grep -m1 '^ListenPort' /etc/wireguard/wg0.conf | awk -F '=' '{print $2}' | xargs)
  fi
  if [[ -z "$WG_PORT_CLEAN" ]]; then
    WG_PORT_CLEAN=51820
  fi
  if command -v ufw >/dev/null 2>&1; then
    sudo ufw delete allow ${WG_PORT_CLEAN}/udp 2>/dev/null || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && sudo systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --remove-port=${WG_PORT_CLEAN}/udp --permanent 2>/dev/null || true
    sudo firewall-cmd --reload 2>/dev/null || true
  fi

  # Remove configs/keys and try unloading kernel module
  sudo rm -rf /etc/wireguard 2>/dev/null || true
  if lsmod | grep -q '^wireguard\b'; then
    sudo modprobe -r wireguard 2>/dev/null || true
  fi

  # Purge packages
  if command -v apt >/dev/null 2>&1; then
    sudo apt purge -y wireguard wireguard-tools resolvconf 2>/dev/null || true
    sudo apt autoremove -y 2>/dev/null || true
  fi

  echo "[INFO] WireGuard fully uninstalled and cleaned up."
}

# Dispatch commands
v="${1:-help}"
shift || true
case "${v}" in
  "init") cmd_init ;;
  "start") cmd_start ;;
  "stop") cmd_stop ;;
  "restart") cmd_restart ;;
  "status") cmd_status ;;
  "uninstall-wireguard") cmd_uninstall_wireguard ;;
  "uninstall-service") cmd_uninstall_service ;;
  "help" | *) cmd_help ;;
esac
