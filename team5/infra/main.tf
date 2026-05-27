terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# ──────────────────────────────────────────
# VPC
# ──────────────────────────────────────────
resource "aws_vpc" "team5_vpc" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "team5-vpc-tf"
  }
}

resource "aws_subnet" "team5_public" {
  vpc_id                  = aws_vpc.team5_vpc.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "team5-subnet-public-tf"
  }
}

resource "aws_internet_gateway" "team5_igw" {
  vpc_id = aws_vpc.team5_vpc.id

  tags = {
    Name = "team5-igw-tf"
  }
}

resource "aws_route_table" "team5_public_rt" {
  vpc_id = aws_vpc.team5_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.team5_igw.id
  }

  tags = {
    Name = "team5-public-rt-tf"
  }
}

resource "aws_route_table_association" "team5_public_rta" {
  subnet_id      = aws_subnet.team5_public.id
  route_table_id = aws_route_table.team5_public_rt.id
}

# ──────────────────────────────────────────
# 보안 그룹
# ──────────────────────────────────────────
resource "aws_security_group" "back_sg" {
  name        = "back-sg-tf"
  description = "Security group for DVWA EC2"
  vpc_id      = aws_vpc.team5_vpc.id

  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip, var.mina_ip]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "TCP 8080"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "back-sg-tf"
  }
}

# ──────────────────────────────────────────
# EC2
# ──────────────────────────────────────────
resource "aws_instance" "dvwa_docker" {
  ami                         = "ami-0c003e98ceffee43e"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.team5_public.id
  vpc_security_group_ids      = [aws_security_group.back_sg.id]
  key_name                    = var.key_pair_name
  associate_public_ip_address = true

  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y docker
    systemctl start docker
    systemctl enable docker
    yum install -y mariadb105 || true
    docker run -d --name dvwa --restart always -p 80:80 tlsehddlf/dvwa-custom:latest
  EOF

  tags = {
    Name = "dvwa-docker-tf"
  }
}

# ──────────────────────────────────────────
# CloudFront
# ──────────────────────────────────────────
resource "aws_cloudfront_distribution" "team5_cf" {
  provider = aws.us_east_1

  origin {
    domain_name = aws_instance.dvwa_docker.public_dns
    origin_id   = "team5-ec2-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled = true
  comment = "team5-cf-tf"

  default_cache_behavior {
    # DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT (알파벳 순서 필수)
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "team5-ec2-origin"

    # CachingDisabled 관리형 정책
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    # AllViewerExceptHostHeader: 쿠키/헤더/쿼리스트링 전달 (DVWA 동적 콘텐츠)
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

    viewer_protocol_policy = "allow-all"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  web_acl_id = aws_wafv2_web_acl.team5_waf.arn

  tags = {
    Name = "team5-cf-tf"
  }

  depends_on = [aws_wafv2_web_acl.team5_waf]
}
