#!/usr/bin/env bash
set -Eeou pipefail

# InvestNet dVPN Node management script
# - Provides commands: init, start, stop, restart, status, uninstall-wireguard, uninstall-service
# - Writes a systemd unit to run the node and syncs WireGuard settings into config.toml
# - Safe by default: strict bash mode, clear logging, and minimal side effects

NODE_DIR="${HOME}/.investnet-dvpnx"
BINARY="${BINARY:-investnet-dvpnx}"  # Default binary name; override by setting $BINARY
API_PORT=18133

PUBLIC_IP=$(curl -fsSL https://ifconfig.me || true)
CHAIN_RPC="https://tendermint.devnet.invest.net"
CHAIN_ID="investnet_7031-1"
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

# Lightweight helpers
log() { echo "[INFO] $*"; }
err() { echo "[ERROR] $*" >&2; }
require() { command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }; }
# Attempt to detect a routable public IP quickly without failing the script
detect_public_ip() { curl -fsSL --max-time 5 https://ifconfig.me || true; }


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
  echo "WireGuard Config:"
  echo "- Address: $WG_ADDRESS"
  echo "- ListenPort: $WG_LISTENPORT"
  echo "- PrivateKey: $PRIVATE_KEY"
else
  echo "WireGuard config not found at $WG_CONF"
fi

# Update ~/.investnet-dvpnx/config.toml [wireguard] section with values from wg0.conf
if [[ -f "$CONFIG_TOML" ]]; then
  # Only update when all required fields are available
  if [[ -n "$WG_ADDRESS" && -n "$WG_LISTENPORT" && -n "$WG_PRIVATEKEY" ]]; then
    echo "Updating $CONFIG_TOML [wireguard] ipv4_addr, port, private_key"
    # Create a timestamped backup before in-place edits
    cp "$CONFIG_TOML" "${CONFIG_TOML}.bak.$(date +%s)"
    # Replace only inside [wireguard] section using a bounded sed range
    sed -i -E '/^\[wireguard\]/,/^\[/ {
      s|^ipv4_addr = .*|ipv4_addr = '"'"${WG_ADDRESS//&/\\&}"'"'|
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
  # Emit a minimal, resilient unit file to run the node as the current user
  sudo bash -c "cat > ${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=InvestNet dVPN Node
Wants=network-online.target
After=network-online.target

[Service]
User=$(whoami)
Group=$(whoami)
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
}


# Initialize node: ensure binary, create config, and add keys
function cmd_init {
  # --- WireGuard prerequisite check ---
  if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
    err "WireGuard is not installed. Please install it before initializing the node."
    echo "On Ubuntu: sudo apt install wireguard wireguard-tools"
    exit 1
  fi


 # --- Go Installation Check ---
if ! command -v go &> /dev/null; then
  echo "Go not found.  Installing Go. with ./install-go.sh"
  echo "after go install run 'source ~/.profile' to update your environment."
  exit 1
  # bash "$(dirname "$0")/install-go.sh"
  # Reload env so newly installed Go is available in this session
  # source ~/.profile
  # source ~/.bashrc
  # echo "Go installed and environment updated."
else
  echo "Go is already installed. Skipping installation."
fi

# --- Binary Auto-Download from GitHub ---
if ! command -v "${BINARY}" &> /dev/null; then
  echo "[INFO] ${BINARY} not found — downloading from GitHub release"

  VERSION="1.0.0"
  DOWNLOAD_URL="https://github.com/akshiiitt/node-local-binary/releases/download/${VERSION}/investnet-dvpnx-linux-amd64"

  echo "[INFO] Downloading: ${DOWNLOAD_URL}"

  curl -L "${DOWNLOAD_URL}" -o "/tmp/${BINARY}" \
    || { echo "[ERROR] Failed to download binary"; exit 1; }

  echo "[INFO] Verifying checksum..."
  echo "ba9b3ed59482021f2b1964393e1645bb7115a064fb93a82a048a604450c1d3af  /tmp/${BINARY}" | sha256sum -c - \
    || { echo "[ERROR] Checksum verification failed"; exit 1; }

  chmod +x "/tmp/${BINARY}"
  sudo mv "/tmp/${BINARY}" "/usr/local/bin/${BINARY}"

  echo "[INFO] Installed ${BINARY} at /usr/local/bin/${BINARY}"
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
  GIGABYTE_PRICES="${DENOM}:0.0025,12500000"
  HOURLY_PRICES="${DENOM}:0.005,25000000"

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
  if [[ -f "${NODE_DIR}/config.toml" ]]; then
    # Use sed to update the from_name field
    if sed -i "s/^from_name = .*/from_name = \"${ACCOUNT_NAME}\"/" "${NODE_DIR}/config.toml"; then
      echo "Updated from_name to '${ACCOUNT_NAME}' in config.toml"
    else
      echo "Warning: Failed to update from_name in config.toml"
    fi
  fi

  echo "====================================================================================="
  echo "IMPORTANT: Save the mnemonics and key address to a safe place!"
  echo "Make sure the key has balance before running START command."
}


# Configure and start the node via systemd, then report basic health info
function cmd_start {
    # Proactively bring down wg0 to avoid stale state (ignore errors)
    wg-quick down wg0 || true
    if [[ ! -f "${NODE_DIR}/config.toml" ]]; then
      err "Config file not found at ${NODE_DIR}/config.toml"; exit 1
    fi

    # Sync [wireguard] section in config.toml from /etc/wireguard/wg0.conf
    update_wireguard_config_from_wg

    # Read dynamic settings from config.toml; fail fast if missing
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

    # Ensure an up-to-date systemd unit and enable it
    write_systemd_unit
    sudo systemctl daemon-reload
    sudo systemctl enable investnet-dvpn-node.service 
    sudo systemctl start investnet-dvpn-node.service 

    log "Waiting 30 seconds for node to initialize..."
    sleep 30
    # Best-effort fetch of node address from local API
    PUB_IP=$(detect_public_ip)
    if [[ -n "$PUB_IP" ]]; then
      NODE_ADDR=$(curl -sk "https://$PUB_IP:$API_PORT_CFG" | jq -r '.result.addr' || true)
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
  journalctl -u investnet-dvpn-node.service -n 50 --no-pager | cat || true
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
  nft delete rule ip wg-nat POSTROUTING oifname "${CLEAN_IFACE}" masquerade 2>/dev/null || true
  nft list chains ip wg-nat >/dev/null 2>&1 && nft flush chain ip wg-nat POSTROUTING 2>/dev/null || true
  nft list tables ip | grep -q wg-nat && nft delete table ip wg-nat 2>/dev/null || true

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
