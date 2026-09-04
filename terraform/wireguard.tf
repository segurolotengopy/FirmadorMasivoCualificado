############################################################
# Gateway WireGuard (extremo AWS de los túneles hacia Paraguay)
#
# Diseño:
#   - Una instancia pequeña en subred pública con EIP fija (endpoint estable para los nodos).
#   - ENI dedicada con source_dest_check = false: actúa como router entre la VPC y la red overlay.
#   - Las claves WireGuard se generan EN la instancia en el primer arranque y se persisten en
#     SSM Parameter Store (SecureString, KMS). Nunca pasan por el estado de Terraform.
#   - La clave pública del gateway se publica en SSM para que Ansible la lea al configurar los nodos.
#   - Auto-recuperación: alarma CloudWatch con acción EC2 recover + user_data idempotente.
############################################################

data "aws_ami" "ubuntu_arm64" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

############################################################
# KMS + SSM: almacenamiento de claves
############################################################
resource "aws_kms_key" "wg" {
  description             = "Cifrado de claves WireGuard (${local.name})"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "wg" {
  name          = "alias/${local.name}-wireguard"
  target_key_id = aws_kms_key.wg.key_id
}

locals {
  ssm_prefix = "/${var.project_name}/${var.environment}/wg"
}

# Parámetros creados vacíos; la instancia los rellena en el primer arranque.
resource "aws_ssm_parameter" "wg_gateway_private_key" {
  name   = "${local.ssm_prefix}/gateway/private_key"
  type   = "SecureString"
  key_id = aws_kms_key.wg.arn
  value  = "PENDING"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "wg_gateway_public_key" {
  name  = "${local.ssm_prefix}/gateway/public_key"
  type  = "String"
  value = "PENDING"

  lifecycle {
    ignore_changes = [value]
  }
}

# PSK por nodo (defensa post-cuántica adicional de WireGuard). Generado en el gateway,
# leído por Ansible desde SSM para escribirlo en el nodo correspondiente.
resource "aws_ssm_parameter" "wg_node_psk" {
  for_each = var.signing_nodes

  name   = "${local.ssm_prefix}/nodes/${each.key}/preshared_key"
  type   = "SecureString"
  key_id = aws_kms_key.wg.arn
  value  = "PENDING"

  lifecycle {
    ignore_changes = [value]
  }
}

############################################################
# IAM del gateway (SSM Session Manager + acceso a sus parámetros + logs)
############################################################
resource "aws_iam_role" "wg_gateway" {
  name = "${local.name}-wg-gateway-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "wg_gateway_ssm" {
  role       = aws_iam_role.wg_gateway.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "wg_gateway_cw" {
  role       = aws_iam_role.wg_gateway.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy" "wg_gateway_params" {
  name = "${local.name}-wg-gateway-params"
  role = aws_iam_role.wg_gateway.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:PutParameter"]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${local.ssm_prefix}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.wg.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "wg_gateway" {
  name = "${local.name}-wg-gateway-profile"
  role = aws_iam_role.wg_gateway.name
}

data "aws_caller_identity" "current" {}

############################################################
# Security Group del gateway
############################################################
resource "aws_security_group" "wg_gateway" {
  name        = "${local.name}-sg-wg-gateway"
  description = "Gateway WireGuard: UDP desde sedes Paraguay; trafico overlay hacia ALB"
  vpc_id      = aws_vpc.core.id

  ingress {
    description = "WireGuard UDP desde Paraguay"
    from_port   = var.wg_listen_port
    to_port     = var.wg_listen_port
    protocol    = "udp"
    cidr_blocks = var.wg_allowed_source_cidrs
  }

  # El ALB (subredes privadas) envía peticiones a las IPs overlay; el tráfico entra
  # por esta ENI para ser encapsulado. Se permite solo el puerto de la API.
  ingress {
    description     = "API de firma desde el ALB hacia nodos (via overlay)"
    from_port       = var.api_port
    to_port         = var.api_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  dynamic "ingress" {
    for_each = length(var.admin_ssh_cidrs) > 0 ? [1] : []
    content {
      description = "SSH administracion (Bolivia)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.admin_ssh_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-sg-wg-gateway" }
}

############################################################
# ENI + instancia + EIP
############################################################
resource "aws_network_interface" "wg_gateway" {
  subnet_id         = aws_subnet.public[0].id
  security_groups   = [aws_security_group.wg_gateway.id]
  source_dest_check = false # imprescindible para enrutar la red overlay

  tags = { Name = "${local.name}-eni-wg-gateway" }
}

resource "aws_eip" "wg_gateway" {
  domain            = "vpc"
  network_interface = aws_network_interface.wg_gateway.id
  tags              = { Name = "${local.name}-eip-wg-gateway" }
}

resource "aws_instance" "wg_gateway" {
  ami                  = data.aws_ami.ubuntu_arm64.id
  instance_type        = var.wg_gateway_instance_type
  iam_instance_profile = aws_iam_instance_profile.wg_gateway.name

  network_interface {
    network_interface_id = aws_network_interface.wg_gateway.id
    device_index         = 0
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 obligatorio
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 10
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user_data/wg-gateway.sh.tpl", {
    aws_region       = var.aws_region
    ssm_prefix       = local.ssm_prefix
    wg_address       = var.wg_gateway_address
    wg_cidr          = var.wg_cidr
    wg_listen_port   = var.wg_listen_port
    vpc_cidr         = var.vpc_cidr
    log_group        = aws_cloudwatch_log_group.wg_gateway.name
    peers            = var.signing_nodes
    signing_api_port = var.api_port
  })
  user_data_replace_on_change = true

  tags = { Name = "${local.name}-wg-gateway" }

  lifecycle {
    ignore_changes = [ami] # evitar reemplazos involuntarios por AMIs nuevas
  }
}

############################################################
# Auto-recuperación y observabilidad del gateway
############################################################
resource "aws_cloudwatch_log_group" "wg_gateway" {
  name              = "/${var.project_name}/${var.environment}/wg-gateway"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_metric_alarm" "wg_gateway_recover" {
  alarm_name          = "${local.name}-wg-gateway-system-recover"
  alarm_description   = "Recuperacion automatica del gateway WireGuard ante fallo de hardware/host"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions          = { InstanceId = aws_instance.wg_gateway.id }

  alarm_actions = concat(
    ["arn:aws:automate:${var.aws_region}:ec2:recover"],
    var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  )
}

# Métrica custom publicada por el gateway (script wg-health): peers con handshake < 180 s.
resource "aws_cloudwatch_metric_alarm" "wg_peers_down" {
  alarm_name          = "${local.name}-wg-peers-degraded"
  alarm_description   = "Menos de 2 nodos de firma con handshake WireGuard reciente"
  namespace           = "FirmaF2/WireGuard"
  metric_name         = "PeersUp"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 2
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}
