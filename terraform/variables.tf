############################################################
# Identidad y región
############################################################
variable "project_name" {
  description = "Nombre corto del proyecto (usado como prefijo de recursos)."
  type        = string
  default     = "firma-f2"
}

variable "environment" {
  description = "Entorno lógico: dev | staging | prod."
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "Región AWS. sa-east-1 (São Paulo) es la de menor latencia hacia Paraguay/Bolivia."
  type        = string
  default     = "sa-east-1"
}

############################################################
# Red (VPC)
############################################################
variable "vpc_cidr" {
  description = "CIDR de la VPC core."
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Subredes públicas (gateway WireGuard). Dos AZs para tolerancia a fallos."
  type        = list(string)
  default     = ["10.10.0.0/24", "10.10.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Subredes privadas (ALB interno + plataforma SaaS consumidora)."
  type        = list(string)
  default     = ["10.10.10.0/24", "10.10.11.0/24"]
}

############################################################
# WireGuard
############################################################
variable "wg_cidr" {
  description = "Red overlay de los túneles WireGuard (no debe solaparse con vpc_cidr ni con las LAN de Paraguay)."
  type        = string
  default     = "10.200.0.0/24"
}

variable "wg_gateway_address" {
  description = "IP del extremo AWS dentro de la red overlay WireGuard."
  type        = string
  default     = "10.200.0.1"
}

variable "wg_listen_port" {
  description = "Puerto UDP de escucha de WireGuard en el gateway AWS."
  type        = number
  default     = 51820
}

variable "wg_allowed_source_cidrs" {
  description = <<-EOT
    CIDRs públicos desde los que se acepta UDP/51820 (IPs públicas de las sedes en Paraguay).
    WireGuard es silencioso ante paquetes no autenticados, por lo que 0.0.0.0/0 es aceptable
    si las IPs de las sedes son dinámicas; restringir cuando sean estáticas.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "signing_nodes" {
  description = <<-EOT
    Nodos transaccionales (MiniPCs) en Paraguay. La clave pública WireGuard de cada nodo se genera
    en el propio nodo (nunca sale de él) y se copia aquí. La IP overlay es la que el ALB usará como target.
  EOT
  type = map(object({
    wg_address = string # IP overlay del nodo, ej. 10.200.0.11
    wg_pubkey  = string # clave pública WireGuard del nodo
    location   = string # etiqueta informativa: sede / rack
  }))
  default = {
    node-py-01 = { wg_address = "10.200.0.11", wg_pubkey = "REEMPLAZAR_PUBKEY_NODO_01", location = "Asunción - Sede A" }
    node-py-02 = { wg_address = "10.200.0.12", wg_pubkey = "REEMPLAZAR_PUBKEY_NODO_02", location = "Asunción - Sede A" }
    node-py-03 = { wg_address = "10.200.0.13", wg_pubkey = "REEMPLAZAR_PUBKEY_NODO_03", location = "Asunción - Sede B" }
  }
}

variable "wg_gateway_instance_type" {
  description = "Tipo de instancia del gateway WireGuard. t4g.micro (ARM) es suficiente para el volumen de firmas."
  type        = string
  default     = "t4g.micro"
}

############################################################
# ALB / API de firma
############################################################
variable "api_port" {
  description = "Puerto en el que escucha el microservicio FastAPI en cada nodo."
  type        = number
  default     = 8443
}

variable "api_protocol" {
  description = "Protocolo ALB -> nodo. HTTPS con certificado interno en los nodos; HTTP solo si se asume que el túnel WireGuard ya cifra (defensa en profundidad recomienda HTTPS)."
  type        = string
  default     = "HTTPS"
  validation {
    condition     = contains(["HTTP", "HTTPS"], var.api_protocol)
    error_message = "api_protocol debe ser HTTP o HTTPS."
  }
}

variable "alb_certificate_arn" {
  description = "ARN del certificado ACM (privado o público) para el listener HTTPS del ALB interno. Vacío = listener HTTP (solo dev)."
  type        = string
  default     = ""
}

variable "api_consumer_sg_ids" {
  description = "Security Groups de la plataforma SaaS autorizados a invocar el ALB (ECS tasks, Lambdas, EC2)."
  type        = list(string)
  default     = []
}

variable "api_consumer_cidrs" {
  description = "CIDRs adicionales autorizados a invocar el ALB (ej. VPN de administración desde Bolivia para pruebas)."
  type        = list(string)
  default     = []
}

variable "health_check_path" {
  description = "Ruta de health check del microservicio. Devuelve 503 si el token no está visible."
  type        = string
  default     = "/health"
}

############################################################
# Operación
############################################################
variable "admin_ssh_cidrs" {
  description = "CIDRs con acceso SSH al gateway WireGuard (VPN de administración Bolivia). Vacío = solo SSM Session Manager."
  type        = list(string)
  default     = []
}

variable "alarm_sns_topic_arn" {
  description = "ARN del tópico SNS para alarmas (túnel caído, nodos sin salud). Vacío = sin notificaciones."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Retención de logs en CloudWatch (auditoría de firmas)."
  type        = number
  default     = 400
}
