# ──────────────────────────────────────────
# 보안 그룹 - OpenSearch
# ──────────────────────────────────────────
resource "aws_security_group" "opensearch_sg" {
  name        = "opensearch-sg-tf"
  description = "Security group for OpenSearch EC2"
  vpc_id      = aws_vpc.team5_vpc.id

  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip, var.mina_ip]
  }

  ingress {
    description = "OpenSearch API"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]
  }

  ingress {
    description = "OpenSearch API test"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "OpenSearch Dashboards"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip, var.mina_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "opensearch-sg-tf"
  }
}

# ──────────────────────────────────────────
# EC2 - OpenSearch
# ──────────────────────────────────────────
resource "aws_instance" "opensearch" {
  ami                         = "ami-0c9c942bd7bf113a2"
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.team5_public.id
  vpc_security_group_ids      = [aws_security_group.opensearch_sg.id]
  key_name                    = var.key_pair_name
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    set -e

    apt-get update -y
    apt-get upgrade -y
    apt-get install -y openjdk-17-jdk curl gnupg

    curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp \
      | gpg --dearmor -o /usr/share/keyrings/opensearch-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" \
      | tee /etc/apt/sources.list.d/opensearch-2.x.list

    apt-get update -y
    OPENSEARCH_INITIAL_ADMIN_PASSWORD=${var.opensearch_password} apt-get install -y opensearch

    systemctl enable opensearch
    systemctl start opensearch

    for i in $(seq 1 12); do
      curl -sk https://localhost:9200 -u admin:${var.opensearch_password} --insecure && break
      sleep 5
    done

    curl -sk -X PUT "https://localhost:9200/logs-waf" \
      -u admin:${var.opensearch_password} --insecure \
      -H 'Content-Type: application/json' -d '{
        "mappings": {
          "properties": {
            "timestamp": { "type": "date" },
            "severity":  { "type": "keyword" },
            "source":    { "type": "keyword" },
            "src_ip":    { "type": "ip" },
            "action":    { "type": "keyword" },
            "message":   { "type": "text" }
          }
        }
      }'

    curl -sk -X PUT "https://localhost:9200/logs-ec2" \
      -u admin:${var.opensearch_password} --insecure \
      -H 'Content-Type: application/json' -d '{
        "mappings": {
          "properties": {
            "timestamp": { "type": "date" },
            "severity":  { "type": "keyword" },
            "source":    { "type": "keyword" },
            "src_ip":    { "type": "ip" },
            "dst_ip":    { "type": "ip" },
            "action":    { "type": "keyword" },
            "message":   { "type": "text" }
          }
        }
      }'

    curl -sk -X PUT "https://localhost:9200/logs-cloudtrail" \
      -u admin:${var.opensearch_password} --insecure \
      -H 'Content-Type: application/json' -d '{
        "mappings": {
          "properties": {
            "timestamp": { "type": "date" },
            "severity":  { "type": "keyword" },
            "source":    { "type": "keyword" },
            "src_ip":    { "type": "ip" },
            "action":    { "type": "keyword" },
            "message":   { "type": "text" }
          }
        }
      }'
  EOF

  tags = {
    Name = "opensearch-tf"
  }
}

output "opensearch_public_ip" {
  description = "OpenSearch EC2 퍼블릭 IP"
  value       = aws_instance.opensearch.public_ip
}