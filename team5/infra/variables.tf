variable "admin_ip" {
  description = "관리자 IP (CIDR 형식, 예: 1.2.3.4/32) - SSH 접근 허용 IP"
}

variable "mina_ip" {
  description = "팀원 IP (CIDR 형식, 예: 1.2.3.4/32) - SSH 접근 허용 IP"
}

variable "alert_email" {
  description = "보안 알림을 받을 이메일 주소 (AWS SES 인증 필요)"
}

variable "account_id" {
  description = "AWS 계정 ID (12자리 숫자)"
}

variable "key_pair_name" {
  description = "EC2에 사용할 키페어 이름 (AWS 콘솔에서 미리 생성 필요)"
}

variable "discord_webhook_url" {
  description = "Discord Webhook URL (보안 알림 전송용)"
  sensitive   = true
}

variable "rds_password" {
  description = "RDS MySQL 비밀번호"
  sensitive   = true
}
