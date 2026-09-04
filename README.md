# Ecosistema de Firma Electrónica Cualificada F2 — AWS · Paraguay · Bolivia

Plataforma transaccional de firma PAdES con tokens criptográficos F2 (FIPS 140-2 L3) para el mercado
asegurador paraguayo, orquestada desde AWS y administrada remotamente desde Bolivia. Sustituye el
modelo de "firmador masivo por carpetas" (latencia de 30 s, un token por instancia, sin alertas) por
una API síncrona (< 2 s), tres nodos redundantes y telemetría con auditoría inmutable.

```
                 ┌──────────────────────────── AWS (sa-east-1) ─────────────────────────────┐
                 │  Plataforma SaaS ──HTTPS──▶ ALB interno ──▶ TG (ip targets 10.200.0.11-13) │
                 │        (subredes privadas)      │  least_outstanding_requests             │
                 │                                 ▼                                         │
                 │   ruta 10.200.0.0/24 ──▶ ENI gateway WireGuard (EIP, UDP 51820)           │
                 └─────────────────────────────────┬─────────────────────────────────────────┘
                                   túneles WG exclusivos (1 peer/nodo, PSK, /32)
              ┌───────────────────────────────────┼───────────────────────────────────┐
              ▼                                   ▼                                   ▼
   ┌─ node-py-01 (Sede A) ─┐          ┌─ node-py-02 (Sede A) ─┐          ┌─ node-py-03 (Sede B) ─┐
   │ Ubuntu Minimal        │          │                       │          │                       │
   │ wg0 10.200.0.11       │          │ wg0 10.200.0.12       │          │ wg0 10.200.0.13       │
   │ firma-api :8443 (TLS) │          │ firma-api :8443       │          │ firma-api :8443       │
   │ pcscd + OpenSC PKCS#11│          │                       │          │                       │
   │ udev → /dev/token-f2  │          │                       │          │                       │
   │ [USB] Token F2 (serie)│          │ [USB] Token F2        │          │ [USB] Token F2        │
   └───────────────────────┘          └───────────────────────┘          └───────────────────────┘
              ▲  Ansible (SSH por la overlay) + telemetría ◀── Centro de gestión (Bolivia)
```

## Estructura del repositorio

| Directorio | Misión | Contenido |
|---|---|---|
| `terraform/` | 1 · IaC y red segura | VPC, subredes, rutas hacia la overlay, gateway WireGuard (claves en SSM/KMS), ALB interno con targets IP, logs WORM, alarmas |
| `wireguard/` | 1 · Túneles | Plantillas estandarizadas nodo/gateway y política nftables del nodo |
| `ansible/` | 2 · Automatización de nodos | `site.yml` + roles `common`, `pcsc`, `udev_token`, `wireguard`, `firma_api`, `watchdog`; playbooks de bootstrap, descubrimiento y rotación |
| `api/` | 3 · Microservicio criptográfico | FastAPI + pyHanko + python-pkcs11; firma en memoria, health profundo, auditoría encadenada, integración systemd (`Type=notify`, watchdog, `SIGUSR1`) |
| `docs/` | — | Arquitectura, decisiones de diseño y matriz de fallos |
| `client/` | — | Cliente Python de referencia para la plataforma SaaS |

## Decisiones de diseño relevantes

* **ALB con targets IP fuera de la VPC.** El ALB admite IPs RFC1918 enrutables; la ruta `10.200.0.0/24 → ENI del gateway` las hace alcanzables. El algoritmo `least_outstanding_requests` envía cada petición al nodo con menos peticiones en vuelo (menor carga transaccional). El ALB no mide latencia geográfica: con 3 nodos en el mismo país el criterio correcto es la carga.
* **Un peer por nodo, `AllowedIPs /32`, PSK.** WireGuard usa *cryptokey routing*: cada nodo solo puede emitir/recibir con su IP; un nodo comprometido no puede suplantar a otro. Los nodos inician el túnel (NAT en la sede) con `PersistentKeepalive=20`.
* **Claves nunca en el estado de Terraform.** El gateway genera su par de claves y las PSK en el primer arranque y las persiste en SSM Parameter Store (SecureString, KMS). Las claves privadas de los nodos se generan en cada MiniPC y no salen de ellas.
* **Token anclado por número de serie (udev).** Independientemente del puerto o del orden de enumeración, el token correcto es `/dev/token-f2`; un token ajeno de la misma familia no se ancla. La conexión dispara `token-f2-attached.service` (reinicio de `pcscd` + `SIGUSR1` a la API); la extracción invalida la sesión PKCS#11.
* **Selección del certificado de firma.** Los tokens cualificados suelen traer certificado de autenticación y de firma. El servicio elige el que tiene `keyUsage nonRepudiation` y clave privada en el token (emparejados por `CKA_ID`), salvo que se fije una etiqueta.
* **Serialización del hardware.** Un token es un canal criptográfico serial: un único hilo de firma por nodo; la concurrencia real la aporta el clúster.
* **Autorrecuperación en 3 niveles.** (1) watchdog de hardware alimentado por systemd; (2) `Restart=always` + `WatchdogSec` en API/pcscd/wg0; (3) `firma-selfcheck` funcional cada minuto con escalado: reiniciar pcscd → reiniciar API → reset lógico del puerto USB. Un hilo bloqueado en el driver "envenena" el proceso: deja de alimentar el watchdog y systemd lo reinicia.
* **Auditoría inmutable.** `audit.jsonl` encadenado por SHA-256 (`prev_hash`/`hash`), `fsync` por registro, `ProtectSystem=strict`; envío asíncrono al colector en AWS; logs del ALB en S3 versionado.
* **Todo en memoria.** El PDF entra en Base64, se decodifica a `BytesIO`, se firma incrementalmente y sale en Base64. Ningún documento toca el disco del nodo.

---

## Guía de despliegue

Convención: **[USTED]** marca los pasos que requieren su intervención (credenciales, autorizaciones, acciones físicas). Todo lo demás lo ejecuta la automatización o puede ejecutarlo el asistente con acceso a la consola.

### Fase 0 · Prerrequisitos

| # | Paso | Responsable |
|---|---|---|
| 0.1 | Cuenta AWS con permisos de administración en `sa-east-1`; credenciales configuradas en el equipo de administración (Bolivia). | **[USTED]** |
| 0.2 | Certificado ACM para el listener del ALB (ACM Private CA recomendada; o dominio interno). Anotar el ARN. | **[USTED]** (emisión) |
| 0.3 | 3 MiniPCs x86-64 con Ubuntu Server 24.04 Minimal, usuario `opsadmin` con clave SSH pública instalada, conectadas a la LAN de cada sede con salida a Internet (UDP 51820 saliente, HTTPS saliente). | **[USTED]** (instalación física; puede delegarse a la sede en Paraguay) |
| 0.4 | Tokens F2 emitidos por la certificadora (Confirma) con su PIN. Un token por nodo. | **[USTED]** |
| 0.5 | Equipo de administración con Terraform ≥ 1.6, Ansible ≥ 2.15, `ansible-vault`, AWS CLI. | automatizable |

### Fase 1 · Bootstrap de los nodos (por la LAN de la sede)

1. Generar las claves WireGuard en cada nodo (no salen del equipo) y obtener sus claves públicas:
   ```
   cd ansible
   ansible-playbook playbooks/00-bootstrap-keys.yml -i <ip_lan_nodo>, -u opsadmin
   ```
2. Descubrir el token de cada nodo (VID:PID, número de serie, etiquetas PKCS#11):
   ```
   ansible-playbook playbooks/01-discover-token.yml -i <ip_lan_nodo>, -u opsadmin
   ```
   Completar `inventory/host_vars/node-py-0N.yml` con `token_vendor_id`, `token_product_id`, `token_serial`.
   Si la salida de `pkcs11-tool -L` no muestra el token con OpenSC, la certificadora debe entregar el driver `.so` para Linux (**[USTED]** solicitarlo); se despliega con `proprietary_pkcs11_deb` y `pkcs11_module_path` en el rol `pcsc`.

### Fase 2 · Infraestructura AWS (Terraform)

1. `cp terraform/terraform.tfvars.example terraform/terraform.tfvars` y completar: claves públicas de los nodos (fase 1), ARN del certificado, SG de la plataforma SaaS, tópico SNS.
2. `terraform init && terraform plan` → revisar el plan.
3. **[USTED]** Autorizar `terraform apply` (crea recursos facturables: EIP, EC2 t4g.micro, ALB, KMS, S3).
4. Al finalizar, el gateway arranca y en ~2 minutos publica su clave pública en SSM. Recuperar los datos para Ansible:
   ```
   terraform output wg_gateway_endpoint
   aws ssm get-parameter --name /firma-f2/prod/wg/gateway/public_key --query Parameter.Value --output text
   aws ssm get-parameter --name /firma-f2/prod/wg/nodes/node-py-01/preshared_key --with-decryption --query Parameter.Value --output text   # ×3
   ```

### Fase 3 · Secretos y aprovisionamiento de nodos (Ansible)

1. Crear `ansible/inventory/group_vars/signing_nodes_vault.yml` a partir del `.example` con: PIN del token (**[USTED]** lo proporciona), API key (generar con `openssl rand -hex 32`), endpoint y clave pública del gateway, PSK por nodo.
2. `ansible-vault encrypt inventory/group_vars/signing_nodes_vault.yml` — **[USTED]** define y custodia la contraseña del vault.
3. Primer aprovisionamiento (aún por la LAN; sobrescribir `ansible_host` con `-e` o un inventario temporal):
   ```
   ansible-playbook site.yml --ask-vault-pass
   ```
   Al terminar, cada nodo levanta `wg0`, abre el túnel y la API responde en su IP overlay; el playbook lo verifica (`/health` → 200 con token, 503 sin token).
4. A partir de aquí la administración es por la overlay (`ansible_host: 10.200.0.1N`) a través de la VPN de administración hacia la VPC (SSM Session Manager al gateway o VPN cliente de AWS).

### Fase 4 · Verificación funcional y de failover

| Prueba | Resultado esperado |
|---|---|
| `GET https://<alb_dns>/health` desde la plataforma SaaS | 200 y `HealthyHostCount = 3` en CloudWatch |
| `POST /api/v1/sign-document` (ver `client/`) | 200, `pades_level` según política, PDF válido en Adobe/pyHanko |
| Extraer el token del nodo 1 | `/health` → 503 en ≤ 20 s; ALB retira el nodo; alarma `nodes-unhealthy`; el tráfico sigue en 2 y 3 |
| Reinsertar el token | udev → `token-f2-attached` → API reabre sesión; nodo vuelve al pool en ≤ 20 s sin SSH |
| `systemctl kill -s SIGKILL firma-api` | systemd reinicia en 5 s |
| `systemctl stop pcscd` | selfcheck lo detecta (3 fallos) y lo reinicia; API traduce a `smartcard_daemon_down` (503) mientras tanto |
| Desconectar el cable de red del nodo 2 | handshake caduca; `PeersUp = 2`; `wg-watchdog` reintenta; al reconectar vuelve solo |
| `python -m app.audit verify /var/log/firma-api/audit.jsonl` | "cadena íntegra" |

**[USTED]** Las pruebas físicas (extraer token, cable) requieren coordinación con la sede en Paraguay.

### Fase 5 · Go-live

**[USTED]**: inserción de los tokens oficiales, PIN definitivo (rotar con `playbooks/02-rotate-pin.yml`), apuntar la plataforma SaaS al `alb_dns_name` con la API key definitiva, y suscribir al equipo al tópico SNS de alarmas.

---

## Operación diaria (Bolivia)

* Estado del clúster: CloudWatch `HealthyHostCount`, `FirmaF2/WireGuard PeersUp`; `/health` de cada nodo incluye `days_to_expiry` del certificado (alerta a ≤ 30 días: reemplaza la dependencia del correo de la certificadora).
* Parches: `ansible-playbook site.yml --tags common` (los paquetes criptográficos están en lista negra de `unattended-upgrades`; se actualizan deliberadamente con `--tags pcsc`).
* Rotación de PIN/API key: `playbooks/02-rotate-pin.yml`.
* Renovación de certificado: la certificadora entrega un token nuevo en la sede (**[USTED]** coordina); ejecutar `01-discover-token.yml`, actualizar `token_serial` en `host_vars` y `site.yml --tags udev,api`.
* Auditoría: `audit.jsonl` (encadenado) + `hardware-events.jsonl` en cada nodo; logs del ALB en S3 (versionado); VPC Flow Logs.

## Pruebas del microservicio (sin hardware)

```
cd api && pip install -r requirements.txt pytest cryptography
FIRMA_API_KEY=test-key FIRMA_AUDIT_LOG=/tmp/audit-test.jsonl python -m pytest -q
```
Las pruebas firman un PDF real en memoria con un firmante software, validan la firma con pyHanko y verifican la cadena de auditoría y el mapeo de errores PKCS#11 (13 pruebas).
