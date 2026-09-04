# Arquitectura y matriz de fallos

## Flujo de una firma (camino feliz, ~1–3 s)

1. La plataforma SaaS (subred privada AWS) hace `POST https://<alb>/api/v1/sign-document` con el PDF en Base64.
2. El ALB elige el nodo con menos peticiones en vuelo y lo alcanza vía `10.200.0.1N:8443` (ruta → ENI gateway → wg0 → nodo).
3. `firma-api` valida API key y Base64, decodifica a memoria, calcula SHA-256 de entrada.
4. El worker de firma toma el lock del token; si no hay sesión, abre una (C_Login con PIN), selecciona el certificado con `nonRepudiation` y su clave por `CKA_ID`.
5. pyHanko construye el `SignedData` CMS (PAdES, SHA-256), el token firma el hash (la clave nunca sale del hardware), opcionalmente se solicita el sello de tiempo a la TSA.
6. Se escribe la revisión incremental en `BytesIO`, se calcula SHA-256 de salida, se registra en `audit.jsonl` (hash encadenado) y se responde en Base64.

## Matriz de fallos y respuesta automática

| Evento | Detección | Respuesta | Tiempo | Intervención |
|---|---|---|---|---|
| Token extraído | udev `remove` → `SIGUSR1`; `/health` 503; `CKR_DEVICE_REMOVED` en vuelo → 503 `token_removed_during_operation` | ALB retira el nodo; cliente reintenta en otro nodo | ≤ 20 s | Física (reinsertar) |
| Token reinsertado | udev `add` (serie coincide) → `token-f2-attached.service` | reinicio pcscd + `SIGUSR1`; `/health` 200 | ≤ 20 s | Ninguna |
| Token ajeno insertado | udev (serie no coincide) → evento `foreign` en log | no se ancla; no se firma con él | inmediato | Revisar |
| pcscd caído | `CKR_SESSION_HANDLE_INVALID`/`FUNCTION_FAILED` → 503 `smartcard_daemon_down`; selfcheck ×3 | `Restart=always` pcscd; selfcheck reinicia y avisa a la API | ≤ 3 min | Ninguna |
| Lector colgado (driver bloqueado) | `sign_timeout` 40 s / probe > 8 s | proceso "envenenado" → watchdog systemd lo reinicia; selfcheck ×8 → reset lógico USB | ≤ 1 min | Ninguna |
| API caída (crash) | systemd | `Restart=always`, `RestartSec=5` | 5 s | Ninguna |
| Event loop bloqueado | `WatchdogSec=30` sin `WATCHDOG=1` | SIGABRT + reinicio | 30 s | Ninguna |
| Kernel/systemd congelado | watchdog de hardware (`RuntimeWatchdogSec=30`) | reinicio físico | 30 s | Ninguna |
| Túnel sin handshake | `wg-watchdog` (> 180 s) | reinicia `wg-quick@wg0`; `PeersUp` alarma si < 2 | 1–3 min | Si persiste: red de la sede |
| Gateway AWS con fallo de host | `StatusCheckFailed_System` | EC2 recover (misma ENI/EIP; user_data idempotente) | ~5 min | Ninguna |
| PIN incorrecto | `CKR_PIN_INCORRECT` → 423 `pin_rejected` | se detiene: no reintenta (evita bloqueo por 3 intentos) | inmediato | **Sí**: verificar PIN |
| PIN bloqueado | `CKR_PIN_LOCKED` → 423 `pin_locked` | nodo fuera de pool | inmediato | **Sí**: PUK / certificadora |
| Certificado por vencer | `/health.days_to_expiry ≤ 30` → `warning` | alerta CloudWatch (métrica derivable de logs) | diario | **Sí**: renovar con la certificadora |
| Certificado vencido | `certificate_expired` → 503 | nodo fuera de pool | inmediato | **Sí** |
| Ningún nodo sano | `HealthyHostCount < 1` | alarma CRÍTICA SNS | 1 min | **Sí** |

## Seguridad

* Sin puertos públicos en Paraguay: nftables `policy drop`; API solo por `wg0`; SSH por `wg0` (y LAN como contingencia).
* Túneles con clave por nodo + PSK; `AllowedIPs /32`; el gateway solo reenvía `VPC → nodo:8443` y `nodo → VPC`.
* ALB interno, TLS 1.2/1.3, acceso solo desde los SG de la plataforma; TLS también ALB → nodo (defensa en profundidad dentro del túnel).
* API key con comparación en tiempo constante; sin `/docs` en producción; límite de tamaño y de concurrencia.
* Servicio sin privilegios (`firma`), `ProtectSystem=strict`, `NoNewPrivileges`, `SystemCallFilter`, sin capacidades; el PIN solo en `EnvironmentFile` 0640 root:firma y en el vault de Ansible.
* Claves WireGuard del gateway en SSM SecureString/KMS; claves de nodo generadas en el nodo; IMDSv2 obligatorio.
* Evidencia: auditoría encadenada por hash en cada nodo, eventos de hardware, logs ALB en S3 versionado, VPC Flow Logs.

## Puntos de extensión

* **PAdES-B-LT / LTA**: `embed_validation_info: true` (requiere OCSP/CRL de la certificadora accesibles desde el nodo) y `use_pades_lta` en `signer.py`.
* **Múltiples firmas en un documento**: encadenar llamadas con distinto `field_name` (cada nodo firma con su token; la plataforma orquesta la secuencia).
* **Apariencia de la firma**: `stamp_style` en `PdfSigner` (logo, texto) en `signer.py`.
* **Driver propietario**: `proprietary_pkcs11_deb` + `pkcs11_module_path` (SafeNet `libeToken.so`).
* **Alta disponibilidad del gateway**: pasar la instancia a un ASG de 1 con la ENI adjunta por ciclo de vida, o segundo gateway en otra AZ con doble peer en los nodos.
