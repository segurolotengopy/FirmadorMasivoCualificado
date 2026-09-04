############################################################
# Application Load Balancer interno -> nodos de firma (vía overlay WireGuard)
#
# - target_type = "ip": el ALB admite IPs RFC1918 fuera del CIDR de la VPC siempre que
#   sean enrutables (aquí, vía la ruta wg_cidr -> ENI del gateway).
# - Algoritmo least_outstanding_requests: envía cada petición al nodo con menos
#   peticiones en vuelo, es decir, al de menor carga transaccional / menor latencia efectiva.
# - Health check sobre /health: el microservicio devuelve 503 si el token no es visible,
#   por lo que el ALB retira automáticamente el nodo afectado del pool.
# - stickiness deshabilitado: los nodos son stateless.
############################################################

resource "aws_security_group" "alb" {
  name        = "${local.name}-sg-alb"
  description = "ALB interno de firma: solo consumidores autorizados"
  vpc_id      = aws_vpc.core.id

  dynamic "ingress" {
    for_each = length(var.api_consumer_sg_ids) > 0 ? [1] : []
    content {
      description     = "HTTPS desde plataforma SaaS"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      security_groups = var.api_consumer_sg_ids
    }
  }

  dynamic "ingress" {
    for_each = length(var.api_consumer_cidrs) > 0 ? [1] : []
    content {
      description = "HTTPS desde CIDRs autorizados"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = var.api_consumer_cidrs
    }
  }

  egress {
    description = "Hacia nodos de firma (overlay)"
    from_port   = var.api_port
    to_port     = var.api_port
    protocol    = "tcp"
    cidr_blocks = [var.wg_cidr]
  }

  tags = { Name = "${local.name}-sg-alb" }
}

resource "aws_lb" "signing" {
  name               = "${local.name}-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.private[*].id

  drop_invalid_header_fields = true
  idle_timeout               = 60 # una firma tarda ~1-3 s; 60 s cubre PDFs grandes + TSA

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb"
    enabled = true
  }

  tags = { Name = "${local.name}-alb" }
}

resource "aws_lb_target_group" "signing_nodes" {
  name        = "${local.name}-tg-nodes"
  port        = var.api_port
  protocol    = var.api_protocol
  target_type = "ip"
  vpc_id      = aws_vpc.core.id

  load_balancing_algorithm_type = "least_outstanding_requests"
  deregistration_delay          = 15

  health_check {
    enabled             = true
    path                = var.health_check_path
    protocol            = var.api_protocol
    port                = "traffic-port"
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = { Name = "${local.name}-tg-nodes" }
}

# Cada MiniPC se registra por su IP overlay. availability_zone = "all" es obligatorio
# para targets IP fuera del CIDR de la VPC.
resource "aws_lb_target_group_attachment" "nodes" {
  for_each = var.signing_nodes

  target_group_arn  = aws_lb_target_group.signing_nodes.arn
  target_id         = each.value.wg_address
  port              = var.api_port
  availability_zone = "all"
}

resource "aws_lb_listener" "https" {
  count = var.alb_certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.signing.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.signing_nodes.arn
  }
}

# Listener HTTP solo cuando no hay certificado (entornos dev). En prod debe existir alb_certificate_arn.
resource "aws_lb_listener" "http_dev" {
  count = var.alb_certificate_arn == "" ? 1 : 0

  load_balancer_arn = aws_lb.signing.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.signing_nodes.arn
  }
}

############################################################
# Logs de acceso del ALB (evidencia de cada petición de firma)
############################################################
data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${local.name}-alb-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Object Lock (WORM): los logs no pueden alterarse ni borrarse durante la retención.
resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_elb_service_account.main.arn }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    }]
  })
}

############################################################
# Alarmas del pool de firma
############################################################
resource "aws_cloudwatch_metric_alarm" "unhealthy_nodes" {
  alarm_name          = "${local.name}-nodes-unhealthy"
  alarm_description   = "Al menos un nodo de firma fuera de servicio (token no visible, API caida o tunel roto)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions = {
    LoadBalancer = aws_lb.signing.arn_suffix
    TargetGroup  = aws_lb_target_group.signing_nodes.arn_suffix
  }
  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

resource "aws_cloudwatch_metric_alarm" "no_healthy_nodes" {
  alarm_name          = "${local.name}-nodes-all-down"
  alarm_description   = "CRITICO: ningun nodo de firma disponible"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  dimensions = {
    LoadBalancer = aws_lb.signing.arn_suffix
    TargetGroup  = aws_lb_target_group.signing_nodes.arn_suffix
  }
  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}
