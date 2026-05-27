output "cloudfront_domain" {
  description = "CloudFront 접속 URL"
  value       = "https://${aws_cloudfront_distribution.team5_cf.domain_name}"
}

output "ec2_public_ip" {
  description = "EC2 퍼블릭 IP"
  value       = aws_instance.dvwa_docker.public_ip
}

output "ec2_public_dns" {
  description = "EC2 퍼블릭 DNS"
  value       = aws_instance.dvwa_docker.public_dns
}

output "blocked_ipset_id" {
  description = "BlockedIPSet-tf ID (Lambda 환경변수용)"
  value       = aws_wafv2_ip_set.blocked_ipset.id
}

output "admin_ipset_id" {
  description = "AdminIPSet-tf ID (Lambda 환경변수용)"
  value       = aws_wafv2_ip_set.admin_ipset.id
}

output "rds_endpoint" {
  description = "RDS MySQL 엔드포인트"
  value       = aws_db_instance.team5_rds.address
}
