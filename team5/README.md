# Team5 - AWS 보안 인프라 Terraform

KT Cloud 사이버 보안 2회차 기본 프로젝트  
WAF / CloudFront / Lambda / RDS / DVWA 환경을 Terraform으로 자동 구성합니다.

---

## 구성 요소

| 리소스 | 설명 |
|---|---|
| VPC / Subnet / IGW | ap-northeast-2a, 10.1.0.0/16 |
| EC2 (DVWA) | Docker 기반 취약 웹 앱 (공격 대상) |
| CloudFront | CDN + WAF 연동 |
| WAF v2 | SQL Injection / XSS 등 공격 탐지 및 차단 |
| Lambda | WAF 로그 분석 → Discord / 이메일 알림 |
| RDS MySQL | WAF 공격 탐지 로그 저장 |
| CloudWatch | WAF 로그 수집 및 Lambda 트리거 |

---

## 시작하기

### 1. 사전 준비

- [Terraform](https://developer.hashicorp.com/terraform/install) 설치
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) 설치 및 자격증명 설정

```bash
aws configure
# AWS Access Key ID, Secret Access Key, Region(ap-northeast-2) 입력
```

- AWS 콘솔에서 **EC2 키페어** 미리 생성 (EC2 > 키 페어 > 키 페어 생성)
- AWS **SES**에서 알림 수신 이메일 주소 인증
- AWS **Bedrock** (us-east-1 리전)에서 사용할 모델 접근 권한 활성화

### 2. 레포 클론

```bash
git clone <repo-url>
cd team5_terraform
```

### 3. 변수 파일 생성

`terraform.tfvars`는 개인 정보 보호를 위해 `.gitignore`에 포함되어 있습니다.  
예시 파일을 복사해서 본인 값으로 채워주세요.

```bash
cp infra/terraform.tfvars.example infra/terraform.tfvars
```

`infra/terraform.tfvars`를 열어 아래 항목을 수정합니다:

| 변수 | 설명 | 확인 방법 |
|---|---|---|
| `admin_ip` | 본인 공인 IP (CIDR) | `curl ifconfig.me` 후 `/32` 붙이기 |
| `mina_ip` | 팀원 공인 IP (CIDR) | 팀원에게 확인 |
| `alert_email` | 알림 수신 이메일 | SES 인증 필요 |
| `account_id` | AWS 계정 ID | 콘솔 우측 상단 계정 메뉴 |
| `key_pair_name` | EC2 키페어 이름 | EC2 > 키 페어 |
| `discord_webhook_url` | Discord Webhook URL | 채널 설정 > 연동 > 웹후크 |
| `rds_password` | RDS MySQL 비밀번호 | 직접 설정 (8자 이상) |

### 4. Lambda 패키지 빌드

Lambda 소스코드(`infra/lambda/`)를 zip으로 묶어야 합니다.

```bash
# Linux / Mac
cd infra/lambda && zip -r ../lambda.zip . && cd ../..
```

```powershell
# Windows (PowerShell)
Compress-Archive -Path infra\lambda\* -DestinationPath infra\lambda.zip -Force
```

### 5. Terraform 실행

```bash
cd infra
terraform init
terraform plan
terraform apply
```

> **Windows 환경 주의사항**  
> `terraform init` 후 `Plugin did not respond` 오류가 발생하면 provider 바이너리에 실행 권한이 없는 것입니다.  
> 아래 명령어로 해결합니다:
> ```bash
> chmod +x infra/.terraform/providers/registry.terraform.io/hashicorp/aws/5.*/windows_amd64/terraform-provider-aws_*.exe
> ```

---

## 주의사항

- `terraform.tfvars`는 절대 git에 올리지 마세요. (`.gitignore`에 포함되어 있음)
- `terraform.tfstate` 파일도 git에 올라가지 않도록 주의하세요.
- Lambda는 **us-east-1** 리전에 배포됩니다 (CloudFront WAF 연동 요건).
- RDS 비밀번호는 배포 후 변경 시 `terraform apply`로 반영됩니다.
