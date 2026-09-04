############################################################
# VPC core
############################################################
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name = "${var.project_name}-${var.environment}"
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)
}

resource "aws_vpc" "core" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-igw" }
}

############################################################
# Subredes públicas (gateway WireGuard) y privadas (ALB/SaaS)
############################################################
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.core.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.core.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = { Name = "${local.name}-private-${local.azs[count.index]}", Tier = "private" }
}

############################################################
# Enrutamiento
#   - Público: salida a Internet vía IGW (necesario para el endpoint UDP de WireGuard).
#   - Privado: SIN ruta a Internet. La red overlay WireGuard (wg_cidr) se alcanza
#     a través de la ENI del gateway (source/dest check deshabilitado).
############################################################
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-rt-public" }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "public_to_wg" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = var.wg_cidr
  network_interface_id   = aws_network_interface.wg_gateway.id
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.core.id
  tags   = { Name = "${local.name}-rt-private" }
}

# Ruta crítica: todo tráfico hacia la red overlay se entrega al gateway WireGuard.
resource "aws_route" "private_to_wg" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = var.wg_cidr
  network_interface_id   = aws_network_interface.wg_gateway.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

############################################################
# VPC Endpoints (permiten SSM/CloudWatch desde subredes privadas sin NAT)
############################################################
resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.name}-sg-vpce"
  description = "HTTPS hacia endpoints de interfaz desde la VPC"
  vpc_id      = aws_vpc.core.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["ssm", "ssmmessages", "ec2messages", "logs"])

  vpc_id              = aws_vpc.core.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${local.name}-vpce-${each.key}" }
}

############################################################
# Flow logs (evidencia de red para auditoría)
############################################################
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${local.name}/flow-logs"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.core.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
}
