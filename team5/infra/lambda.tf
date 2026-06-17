# ──────────────────────────────────────────
# CloudWatch Log Group (WAF 로그 수신)
# ──────────────────────────────────────────
resource "aws_cloudwatch_log_group" "waf_logs" {
  provider          = aws.us_east_1
  name              = "aws-waf-logs-team5-tf"
  retention_in_days = 30
}

# WAF → CloudWatch Logs 전송을 위한 리소스 기반 정책
resource "aws_cloudwatch_log_resource_policy" "waf_log_policy" {
  provider    = aws.us_east_1
  policy_name = "waf-log-resource-policy-tf"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.waf_logs.arn}:*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })
}

# ──────────────────────────────────────────
# WAF 로깅 설정
# ──────────────────────────────────────────
resource "aws_wafv2_web_acl_logging_configuration" "team5_waf_logging" {
  provider                = aws.us_east_1
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.team5_waf.arn

  depends_on = [aws_cloudwatch_log_resource_policy.waf_log_policy]
}

# ──────────────────────────────────────────
# IAM Role for Lambda
# ──────────────────────────────────────────
resource "aws_iam_role" "waf_log_processor_role" {
  name = "waf-log-processor-role-tf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_exec" {
  role       = aws_iam_role.waf_log_processor_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "ses_full_access" {
  role       = aws_iam_role.waf_log_processor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}

resource "aws_iam_role_policy_attachment" "bedrock_full_access" {
  role       = aws_iam_role.waf_log_processor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
}

resource "aws_iam_role_policy_attachment" "waf_full_access" {
  role       = aws_iam_role.waf_log_processor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSWAFFullAccess"
}

# ──────────────────────────────────────────
# Lambda Function
# ──────────────────────────────────────────
resource "aws_lambda_function" "waf_log_processor" {
  provider         = aws.us_east_1
  filename         = "${path.module}/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda.zip")
  function_name    = "waf-log-processor-tf"
  role             = aws_iam_role.waf_log_processor_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      BLOCKED_IPSET_ID    = aws_wafv2_ip_set.blocked_ipset.id
      ADMIN_IPSET_ID      = aws_wafv2_ip_set.admin_ipset.id
      ADMIN_IPS           = replace(var.admin_ip, "/32", "")
      ALERT_EMAIL         = var.alert_email
      DISCORD_WEBHOOK_URL = var.discord_webhook_url
      RDS_HOST            = aws_db_instance.team5_rds.address
      RDS_USER            = "admin"
      RDS_PASSWORD        = var.rds_password
      RDS_DATABASE        = "security_logs"
      OPENSEARCH_ENDPOINT = "http://${aws_instance.opensearch.public_ip}:9200"
      OPENSEARCH_USERNAME = "admin"
      OPENSEARCH_PASSWORD = var.opensearch_password
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_exec,
  ]

  tags = {
    Name = "waf-log-processor-tf"
  }
}

# CloudWatch Logs → Lambda 호출 권한
resource "aws_lambda_permission" "cloudwatch_invoke" {
  provider      = aws.us_east_1
  statement_id  = "AllowCloudWatchLogsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_log_processor.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.waf_logs.arn}:*"
}

# CloudWatch Logs 구독 필터 (WAF 로그 → Lambda 트리거)
resource "aws_cloudwatch_log_subscription_filter" "waf_to_lambda" {
  provider        = aws.us_east_1
  name            = "waf-log-to-lambda-tf"
  log_group_name  = aws_cloudwatch_log_group.waf_logs.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.waf_log_processor.arn

  depends_on = [aws_lambda_permission.cloudwatch_invoke]
}