#!/usr/bin/env bash
# =============================================================================
#  Gateway WireGuard - bootstrap idempotente (renderizado por Terraform)
#  - Genera/recupera claves desde SSM Parameter Store (nunca en el estado TF)
#  - Configura wg0 con un peer por nodo de firma (AllowedIPs /32 => túneles exclusivos)
#  - Publica métrica PeersUp en CloudWatch cada minuto
# =============================================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export AWS_DEFAULT_REGION="${aws_region}"

log() { echo "[wg-bootstrap] $(date -Is) $*" | tee -a /var/log/wg-bootstrap.log; }

# ---------- Paquetes ----------
apt-get update -y
apt-get install -y wireguard wireguard-tools jq unzip curl iptables-persistent

if ! command -v aws >/dev/null 2>&1; then
  ARCH=$(uname -m)
  curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-$${ARCH}.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp && /tmp/aws/install
fi

# ---------- Kernel: forwarding ----------
cat >/etc/sysctl.d/99-wireguard.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl --system >/dev/null

# ---------- Claves del gateway ----------
umask 077
mkdir -p /etc/wireguard
PRIV=$(aws ssm get-parameter --name "${ssm_prefix}/gateway/private_key" --with-decryption --query Parameter.Value --output text)
if [[ "$PRIV" == "PENDING" || -z "$PRIV" ]]; then
  log "Generando par de claves del gateway"
  PRIV=$(wg genkey)
  aws ssm put-parameter --name "${ssm_prefix}/gateway/private_key" --type SecureString --value "$PRIV" --overwrite >/dev/null
  aws ssm put-parameter --name "${ssm_prefix}/gateway/public_key" --type String --value "$(echo "$PRIV" | wg pubkey)" --overwrite >/dev/null
fi
PUB=$(echo "$PRIV" | wg pubkey)
log "Clave publica del gateway: $PUB"

# ---------- PSK por nodo ----------
declare -A PSK
%{ for name, p in peers ~}
PSK["${name}"]=$(aws ssm get-parameter --name "${ssm_prefix}/nodes/${name}/preshared_key" --with-decryption --query Parameter.Value --output text)
if [[ "$${PSK["${name}"]}" == "PENDING" ]]; then
  PSK["${name}"]=$(wg genpsk)
  aws ssm put-parameter --name "${ssm_prefix}/nodes/${name}/preshared_key" --type SecureString --value "$${PSK["${name}"]}" --overwrite >/dev/null
  log "PSK generada para ${name}"
fi
%{ endfor ~}

# ---------- Configuración wg0 ----------
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${wg_address}/24
ListenPort = ${wg_listen_port}
PrivateKey = $PRIV
# Solo se enruta la overlay hacia la VPC y viceversa; sin NAT (el ALB ve la IP real del nodo).
PostUp   = iptables -A FORWARD -i wg0 -d ${vpc_cidr} -j ACCEPT; iptables -A FORWARD -o wg0 -s ${vpc_cidr} -p tcp --dport ${signing_api_port} -j ACCEPT; iptables -A FORWARD -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -A FORWARD -j DROP
PostDown = iptables -F FORWARD

%{ for name, p in peers ~}
# ${name} - ${p.location}
[Peer]
PublicKey    = ${p.wg_pubkey}
PresharedKey = $${PSK["${name}"]}
AllowedIPs   = ${p.wg_address}/32
# Sin Endpoint: los nodos (detrás de NAT en Paraguay) inician el túnel y mantienen keepalive.

%{ endfor ~}
EOF
chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0
log "wg0 activo"

# ---------- Salud del túnel -> CloudWatch ----------
cat >/usr/local/bin/wg-health <<'EOF'
#!/usr/bin/env bash
# Cuenta peers con handshake en los últimos 180 s y publica la métrica PeersUp.
NOW=$(date +%s); UP=0; TOTAL=0
while read -r pub psk endpoint allowed hs rx tx ka; do
  TOTAL=$((TOTAL+1))
  if [[ "$hs" != "0" && $((NOW-hs)) -lt 180 ]]; then UP=$((UP+1)); fi
done < <(wg show wg0 dump | tail -n +2)
aws cloudwatch put-metric-data --namespace FirmaF2/WireGuard \
  --metric-data "MetricName=PeersUp,Value=$UP,Unit=Count" "MetricName=PeersTotal,Value=$TOTAL,Unit=Count"
echo "$(date -Is) peers_up=$UP peers_total=$TOTAL" >> /var/log/wg-health.log
EOF
chmod +x /usr/local/bin/wg-health

cat >/etc/systemd/system/wg-health.service <<'EOF'
[Unit]
Description=Publica salud de peers WireGuard en CloudWatch
After=wg-quick@wg0.service
[Service]
Type=oneshot
Environment=AWS_DEFAULT_REGION=${aws_region}
ExecStart=/usr/local/bin/wg-health
EOF

cat >/etc/systemd/system/wg-health.timer <<'EOF'
[Unit]
Description=Timer de salud WireGuard (1 min)
[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now wg-health.timer

# ---------- Watchdog de systemd para el propio gateway ----------
mkdir -p /etc/systemd/system.conf.d
cat >/etc/systemd/system.conf.d/watchdog.conf <<'EOF'
[Manager]
RuntimeWatchdogSec=30s
RebootWatchdogSec=10min
EOF

log "Bootstrap finalizado. Log group: ${log_group}"
