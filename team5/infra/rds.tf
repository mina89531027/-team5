# ──────────────────────────────────────────
# RDS 전용 VPC (us-east-1)
# ──────────────────────────────────────────
resource "aws_vpc" "rds_vpc" {
  provider             = aws.us_east_1
  cidr_block           = "10.2.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "team5-rds-vpc-tf" }
}

resource "aws_internet_gateway" "rds_igw" {
  provider = aws.us_east_1
  vpc_id   = aws_vpc.rds_vpc.id

  tags = { Name = "team5-rds-igw-tf" }
}

resource "aws_subnet" "rds_subnet_1" {
  provider          = aws.us_east_1
  vpc_id            = aws_vpc.rds_vpc.id
  cidr_block        = "10.2.1.0/24"
  availability_zone = "us-east-1a"

  tags = { Name = "team5-rds-subnet-1-tf" }
}

resource "aws_subnet" "rds_subnet_2" {
  provider          = aws.us_east_1
  vpc_id            = aws_vpc.rds_vpc.id
  cidr_block        = "10.2.2.0/24"
  availability_zone = "us-east-1b"

  tags = { Name = "team5-rds-subnet-2-tf" }
}

resource "aws_route_table" "rds_rt" {
  provider = aws.us_east_1
  vpc_id   = aws_vpc.rds_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.rds_igw.id
  }

  tags = { Name = "team5-rds-rt-tf" }
}

resource "aws_route_table_association" "rds_rt_assoc_1" {
  provider       = aws.us_east_1
  subnet_id      = aws_subnet.rds_subnet_1.id
  route_table_id = aws_route_table.rds_rt.id
}

resource "aws_route_table_association" "rds_rt_assoc_2" {
  provider       = aws.us_east_1
  subnet_id      = aws_subnet.rds_subnet_2.id
  route_table_id = aws_route_table.rds_rt.id
}

# ──────────────────────────────────────────
# RDS 보안 그룹
# ──────────────────────────────────────────
resource "aws_security_group" "rds_sg" {
  provider    = aws.us_east_1
  name        = "rds-sg-tf"
  description = "Security group for RDS MySQL"
  vpc_id      = aws_vpc.rds_vpc.id

  # 관리자 IP 직접 접근 (DB 관리용)
  ingress {
    description = "MySQL from admin"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # Lambda → RDS (Lambda IP가 동적이므로 AWS 네트워크 허용)
  ingress {
    description = "MySQL from Lambda (dynamic IP)"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "rds-sg-tf" }
}

# ──────────────────────────────────────────
# DB Subnet Group
# ──────────────────────────────────────────
resource "aws_db_subnet_group" "team5_rds_subnet" {
  provider   = aws.us_east_1
  name       = "team5-rds-subnet-tf"
  subnet_ids = [aws_subnet.rds_subnet_1.id, aws_subnet.rds_subnet_2.id]

  tags = { Name = "team5-rds-subnet-tf" }
}

# ──────────────────────────────────────────
# RDS MySQL
# ──────────────────────────────────────────
resource "aws_db_instance" "team5_rds" {
  provider               = aws.us_east_1
  identifier             = "team5-rds-tf"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "security_logs"
  username               = "admin"
  password               = var.rds_password
  db_subnet_group_name   = aws_db_subnet_group.team5_rds_subnet.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  publicly_accessible    = true
  skip_final_snapshot    = true

  depends_on = [aws_internet_gateway.rds_igw]

  tags = { Name = "team5-rds-tf" }
}
