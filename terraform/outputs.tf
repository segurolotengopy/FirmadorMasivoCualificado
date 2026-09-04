output "vpc_id" {
  value = aws_vpc.core.id
}

output "private_subnet_ids" {
  description = "Subredes donde desplegar la plataforma SaaS consumidora del ALB."
  value       = aws_subnet.private[*].id
}

output "wg_gateway_public_ip" {
  description = "Endpoint público (EIP) que los nodos en Paraguay usan como Endpoint de WireGuard."
  value       = aws_eip.wg_gateway.public_ip
}

output "wg_gateway_endpoint" {
  value = "${aws_eip.wg_gateway.public_ip}:${var.wg_listen_port}"
}

output "wg_gateway_public_key_ssm" {
  description = "Parámetro SSM con la clave pública del gateway (leído por Ansible)."
  value       = aws_ssm_parameter.wg_gateway_public_key.name
}

output "wg_node_psk_ssm_prefix" {
  description = "Prefijo SSM de las PSK por nodo: <prefijo>/<nombre_nodo>/preshared_key"
  value       = "${local.ssm_prefix}/nodes"
}

output "alb_dns_name" {
  description = "DNS interno del ALB. La plataforma SaaS invoca https://<alb_dns_name>/api/v1/sign-document"
  value       = aws_lb.signing.dns_name
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "signing_nodes_targets" {
  value = { for k, v in var.signing_nodes : k => v.wg_address }
}
