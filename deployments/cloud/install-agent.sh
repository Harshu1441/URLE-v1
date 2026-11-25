#!/usr/bin/env bash
set -euo pipefail

# Universal Linux Cloud VM / Bare-Metal Bootstrap for ULRE Agent (AWS EC2, Azure VM, GCP GCE)
# Usage: ULRE_CONTROL_PLANE=https://cp.example.com ULRE_AGENT_TOKEN=... ./install-agent.sh

CONTROL_PLANE="${ULRE_CONTROL_PLANE:?Set ULRE_CONTROL_PLANE}"
AGENT_TOKEN="${ULRE_AGENT_TOKEN:?Set ULRE_AGENT_TOKEN}"
BIN_URL="${ULRE_AGENT_BIN_URL:-/tmp/ulre-agent}"

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "ERROR: cgroup v2 unified hierarchy not detected at /sys/fs/cgroup" >&2
  exit 1
fi

install -m 0755 "$BIN_URL" /usr/local/bin/ulre-agent
mkdir -p /etc/ulre /var/lib/ulre

cat >/etc/systemd/system/ulre-agent.service <<EOF
[Unit]
Description=Unified Linux Resource Enforcement Agent (ULRE)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ulre-agent enforce --control-plane ${CONTROL_PLANE} --agent-token ${AGENT_TOKEN} --state-dir /var/lib/ulre
Restart=always
RestartSec=5s
Delegate=yes
Slice=ulre.slice
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_KILL
AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_KILL

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ulre-agent.service
systemctl status ulre-agent.service --no-pager
