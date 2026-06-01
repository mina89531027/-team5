import json
import boto3
import gzip
import base64
import os
import urllib.request
import requests
from datetime import datetime, timezone, timedelta
from collections import Counter

try:
    import pymysql
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False


# ─────────────────────────────────────────────
# 설정값
# ─────────────────────────────────────────────
RULE_WEIGHTS = {
    "AWS-AWSManagedRulesSQLiRuleSet":            40,
    "AWS-AWSManagedRulesLinuxRuleSet":           35,
    "AWS-AWSManagedRulesKnownBadInputsRuleSet":  30,
    "BlockedIP-Reaccess":                        30,
    "AdminPath-Protect":                         25,
    "AWS-AWSManagedRulesCommonRuleSet":          40,
    "GlobalRateBasedRule":                       25,
    "AWS-AWSManagedRulesAnonymousIpList":        20,
    "AWS-AWSManagedRulesAmazonIpReputationList": 20,
    "RateBasedRuleGET":                          20,
    "GeoRule":                                   10,
}

ATTACK_KEYWORDS = {
    "union":   15, "select":  10, "insert":  10, "drop":    15,
    "exec":    15, "passwd":  20, "shadow":  20, "etc/":    15,
    "../":     15, "proc/":   20, "script":  10, "onerror": 10,
    "alert(":  10, "or 1=1": 20, "' or":    15, "--":       10,
}

HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR"}

RULE_MAP = {
    "AWS-AWSManagedRulesSQLiRuleSet":            "SQL Injection",
    "AWS-AWSManagedRulesCommonRuleSet":          "공통 공격 (XSS 등)",
    "AWS-AWSManagedRulesLinuxRuleSet":           "Linux 파일 탐색 (LFI)",
    "AWS-AWSManagedRulesKnownBadInputsRuleSet":  "알려진 악성 입력",
    "AWS-AWSManagedRulesAnonymousIpList":        "익명 IP 접근",
    "AWS-AWSManagedRulesAmazonIpReputationList": "악성 IP 접근",
    "GeoRule":                                   "해외 IP 접근",
    "BlockedIP-Reaccess":                        "차단 IP 재접속",
    "AdminPath-Protect":                         "관리자 경로 접근 시도",
    "GlobalRateBasedRule":                       "글로벌 요청 속도 초과",
    "RateBasedRuleGET":                          "GET 요청 속도 초과",
}

TIER_COLOR = {"CRITICAL": 16711680, "WARNING": 16744272, "LOW": 3394611}


# ─────────────────────────────────────────────
# 위험도 점수 산출
# ─────────────────────────────────────────────
def compute_risk_score(block_logs: list, client_ip: str = '') -> dict:
    score        = 0
    rule_counter = Counter()
    keywords     = Counter()

    for log in block_logs:
        if log.get('action') != 'BLOCK':
            continue

        rule = log.get('terminatingRuleId', '')
        rule_counter[rule] += 1
        score += RULE_WEIGHTS.get(rule, 5)

        args = log.get('httpRequest', {}).get('args', '').lower()
        uri  = log.get('httpRequest', {}).get('uri',  '').lower()
        for kw, weight in ATTACK_KEYWORDS.items():
            if kw in args + ' ' + uri:
                keywords[kw] += 1
                score += weight

        if log.get('httpRequest', {}).get('country', '') in HIGH_RISK_COUNTRIES:
            score += 10

    if len(rule_counter) >= 2:
        score += 20
    if len(rule_counter) >= 3:
        score += 15

    abuse_score = check_abuseipdb(client_ip)
    if abuse_score >= 80:
        score += 15
    elif abuse_score >= 50:
        score += 8

    otx_score = check_otx(client_ip)
    if otx_score >= 10:
        score += 15
    elif otx_score >= 5:
        score += 8

    score = min(score, 100)

    if score >= 70:
        tier  = "CRITICAL"
        model = "us.meta.llama3-1-70b-instruct-v1:0"
    elif score >= 30:
        tier  = "WARNING"
        model = "us.meta.llama3-1-8b-instruct-v1:0"
    else:
        tier  = "LOW"
        model = None

    return {
        "score":        score,
        "tier":         tier,
        "model":        model,
        "rule_counter": dict(rule_counter),
        "keywords":     dict(keywords),
    }


# ─────────────────────────────────────────────
# LLM 분석 (8B / 70B 차등)
# ─────────────────────────────────────────────
def ask_llama(client_ip, country, uri, method, rule, args, model_id, tier, rule_counter=None, score=None, correlation_alerts=None):
    bedrock     = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
    log_summary = (f"IP: {client_ip} | 국가: {country} | URI: {uri} | "
                   f"메서드: {method} | 차단규칙: {rule} | 파라미터: {args}")

    if tier == "CRITICAL":
        rule_detail = ""
        if rule_counter:
            for r, cnt in rule_counter.items():
                rk = RULE_MAP.get(r, r)
                rule_detail += f"{rk}: {cnt}건 (IP={client_ip}, Rule={rk})\n"
        total_count = sum(rule_counter.values()) if rule_counter else 1

        # Correlation Rule 위반 내용 추가
        corr_detail = ""
        if correlation_alerts:
            corr_detail = "\nCorrelation Rule 위반 탐지:\n"
            for a in correlation_alerts:
                corr_detail += f"- {a[0]}: {a[1]}\n"

        instruction = (
            f"다음 보안 로그를 심층 분석하여 아래 5개 섹션 형식 그대로 한국어로 작성하세요.\n"
            f"섹션 제목은 변경하지 말고, 각 섹션 내용만 채워 작성하세요.\n"
            f"[공격 정보], [출력 형식] 같은 태그는 출력하지 마세요.\n\n"
            f"공격 정보:\n"
            f"IP: {client_ip} | 국가: {country} | Risk Score: {score}점\n"
            f"감지된 공격 유형 분류 (각 항목은 반드시 줄바꿈으로 구분하여 한 줄씩 출력하세요):\n"
            f"{rule_detail}"
            f"{corr_detail}"
            f"총 {total_count}건 탐지\n\n"
            f"각 공격 유형은 반드시 줄바꿈으로 구분하여 한 줄씩 출력하세요.\n"
            f"아래 형식으로 탐지된 모든 공격을 나열하세요. WAF 탐지와 Correlation Rule 위반 항목을 모두 포함하세요.\n"
            f"형식: [공격유형]: [횟수 또는 건수] (IP={client_ip}, [상세정보])\n"
            f"공격 체인 분석\n\n"
            f"감지된 모든 공격 유형을 종합하여 공격자의 행동 패턴을 1-2문장으로 분석하되 공격별로 줄바꿈.\n\n"
            f"위협 수준\n\n"
            f"심각: Risk Score {score} 기준으로 모든 공격을 종합한 피해 가능성을 설명하세요.\n\n"
            f"대응 권고사항\n\n"
            f"구체적인 대응 방안 3가지, 각각 제목: 설명 형식으로 작성하되 대응별로 줄바꿈.\n\n"
            f"추가 모니터링 포인트\n\n"
            f"(추가 모니터링 권고사항 3가지)"
        )
        max_gen_len = 1024
        #~instruction = (
        #    f"다음 보안 로그를 심층 분석하여 아래 5개 섹션 형식 그대로 한국어로 작성하세요.\n"
        #    f"섹션 제목은 변경하지 말고, 각 섹션 내용만 채워 작성하세요.\n\n"
        #    f"[공격 정보]\n"
        #    f"IP: {client_ip} | 국가: {country} | Risk Score: {score}점\n"
        #    f"감지된 공격:\n{rule_detail}"
        #    f"{corr_detail}"
        #    f"총 {total_count}건 탐지\n\n"
        #    f"[출력 형식]\n"
        #    f"공격 유형 분류\n\n"
        #    f"(각 공격 유형별 건수와 IP 정보 나열)\n\n"
        #    f"공격 체인 분석\n\n"
        #    f"연속 시도: (연속 공격 패턴 분석 1-2문장)\n\n"
        #    f"위협 수준\n\n"
        #    f"심각: (Risk Score {score} 기준 피해 가능성 설명)\n\n"
        #    f"대응 권고사항\n\n"
        #    f"(구체적인 대응 방안 3가지, 각각 제목: 설명 형식)\n\n"
        #    f"추가 모니터링 포인트\n\n"
        #    f"(추가 모니터링 권고사항 3가지)"
        #)
        # max_gen_len = 1024
    else:
        instruction = (
            f"다음 보안 로그를 분석하여 아래 형식에 맞게 정확히 3문장으로 작성하세요.\n\n"
            f"[형식]\n"
            f"1문장: [공격 유형]을 통해 [공격 의도]로 보입니다. [URI]에 [메서드] 방식으로 접근을 시도했습니다.\n"
            f"2문장: 현재 해당 IP {client_ip} 사용자를 차단한 상태이며, 추가 접근 시도가 있을 수 있습니다.\n"
            f"3문장: [관련 시스템 또는 경로]에 문제가 있는지 확인하는 것을 추천드립니다."
        )
        max_gen_len = 512

    prompt = (
        f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
        f"당신은 사이버 보안 관제 전문가입니다. 아래 보안 로그를 분석하여 정해진 형식에 맞게 한국어로 작성하세요.\n"
        f"반드시 아래 형식 그대로 출력하세요. 추가 설명, 번호, 항목명 없이 지정된 섹션만 출력하세요.\n"
        f"<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
        f"{instruction}\n\n"
        f"로그: {log_summary}\n"
        f"<|eot_id|><|start_header_id|>assistant<|end_header_id|>"
    )

    native_request = {
        "prompt": prompt,
        "max_gen_len": max_gen_len,
        "temperature": 0.3,
        "top_p": 0.9,
    }
    response = bedrock.invoke_model(modelId=model_id, body=json.dumps(native_request))
    model_response = json.loads(response["body"].read())
    return model_response.get("generation", "분석 실패").strip()

# ─────────────────────────────────────────────
# IP 차단
# ─────────────────────────────────────────────
def add_ip_to_blocklist(client_ip):
    admin_ips = [ip.strip() for ip in os.environ.get('ADMIN_IPS', '').split(',') if ip.strip()]
    if client_ip in admin_ips:
        print(f"관리자 IP 제외: {client_ip}")
        return

    wafv2    = boto3.client('wafv2', region_name='us-east-1')
    ipset_id = os.environ.get('BLOCKED_IPSET_ID')
    response = wafv2.get_ip_set(Name='BlockedIPSet-tf', Scope='CLOUDFRONT', Id=ipset_id)
    current_addresses = response['IPSet']['Addresses']
    lock_token        = response['LockToken']

    new_ip = f"{client_ip}/32"
    if new_ip in current_addresses:
        print(f"이미 차단된 IP: {client_ip}")
        return

    current_addresses.append(new_ip)
    wafv2.update_ip_set(
        Name='BlockedIPSet-tf', Scope='CLOUDFRONT', Id=ipset_id,
        Addresses=current_addresses, LockToken=lock_token
    )
    print(f"IP 차단 완료: {client_ip}")


# ─────────────────────────────────────────────
# Discord 알림
# ─────────────────────────────────────────────
def send_discord(time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score, model_id=None, correlation_alerts=None):
    # Correlation Rule 위반 내용 공격 기법에 추가
    if correlation_alerts:
        corr_text = "\n".join([a[0] for a in correlation_alerts])
        rule_kor_display = f"{rule_kor}\n{corr_text}"
    else:
        rule_kor_display = rule_kor

    if tier == "CRITICAL":
        title = "🔴 보안 관제 이상 탐지 알림 [심각]"
    else:
        title = "🚨 보안 관제 이상 탐지 알림"

    fields = [
        {"name": "📅 탐지 시각",     "value": time_str,                   "inline": False},
        {"name": "📊 Risk Score",    "value": f"{score} / 100",           "inline": True},
        {"name": "🤖 사용 모델",     "value": model_id or "N/A",          "inline": True},
        {"name": "🌐 공격 IP",       "value": f"{client_ip} ({country})", "inline": False},
        {"name": "⚔️ 공격 기법",     "value": rule_kor_display,           "inline": False},
        {"name": "🛡️ 현재 상태",    "value": "차단됨 (BLOCK)",            "inline": True},
        {"name": "🔗 요청 URL",      "value": uri,                        "inline": False},
        {"name": "📡 요청 방식",     "value": method,                     "inline": True},
        {"name": "📝 공격 파라미터", "value": args or "없음",             "inline": False},
        {"name": "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "value": "🤖 AI 관제 요약", "inline": False},
        {"name": "\u200b",           "value": summary,                    "inline": False},
    ]

    payload = {
        "embeds": [{
            "title":  title,
            "color":  TIER_COLOR[tier],
            "fields": fields,
            "footer": {"text": "⚠️ 즉각적인 확인 및 조치가 필요합니다."},
        }]
    }
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        os.environ.get('DISCORD_WEBHOOK_URL'),
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.7.1"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        print(f"Discord 알림 전송 완료: HTTP {resp.status}")


# ─────────────────────────────────────────────
# 이메일 알림
# ─────────────────────────────────────────────
def send_email(time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score, model_id=None, correlation_alerts=None):
    ses         = boto3.client('ses', region_name='us-east-1')
    alert_email = os.environ.get('ALERT_EMAIL')
    tier_kor    = "심각" if tier == "CRITICAL" else "경고"
    model_name  = model_id or ("Llama 3.1 70B" if tier == "CRITICAL" else "Llama 3.1 8B")
    subject     = f"[보안 관제 {tier_kor}] {rule_kor} 탐지 - {client_ip} ({time_str})"

    # Correlation Rule 위반 내용 추가
    corr_section = ""
    if correlation_alerts:
        corr_section = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        corr_section += "⚠️  Correlation Rule 위반\n"
        corr_section += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        for a in correlation_alerts:
            corr_section += f"• {a[0]}: {a[1]}\n"

    body = f"""
╔══════════════════════════════════════╗
       🚨 보안 관제 이상 탐지 알림 [{tier_kor}]
╚══════════════════════════════════════╝
📅 탐지 시각    : {time_str}
🌐 공격 IP      : {client_ip} ({country})
📊 위험도 점수  : {score}/100 ({tier_kor})
🔗 요청 URL     : {uri}
📡 요청 방식    : {method}
⚔️  공격 기법    : {rule_kor}
📝 공격 파라미터: {args}
🛡️  현재 상태    : 차단됨 (BLOCK)
{corr_section}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 AI 관제 요약 ({model_name})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{summary}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  즉각적인 확인 및 조치가 필요합니다.
    """
    ses.send_email(
        Source=alert_email,
        Destination={'ToAddresses': [alert_email]},
        Message={
            'Subject': {'Data': subject, 'Charset': 'UTF-8'},
            'Body':    {'Text': {'Data': body, 'Charset': 'UTF-8'}},
        }
    )
    print(f"이메일 알림 전송 완료: {client_ip} | {rule_kor} | {tier_kor}")


# ─────────────────────────────────────────────
# MySQL 저장
# ─────────────────────────────────────────────
def save_to_mysql(time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score):
    if not PYMYSQL_AVAILABLE or not os.environ.get('RDS_HOST'):
        return

    try:
        conn = pymysql.connect(
            host=os.environ.get('RDS_HOST'),
            user=os.environ.get('RDS_USER'),
            password=os.environ.get('RDS_PASSWORD'),
            database=os.environ.get('RDS_DATABASE'),
            connect_timeout=5,
            read_timeout=5,
            write_timeout=5,
        )
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    detected_at VARCHAR(50),
                    client_ip   VARCHAR(50),
                    country     VARCHAR(10),
                    uri         VARCHAR(500),
                    method      VARCHAR(10),
                    attack_type VARCHAR(100),
                    parameters  VARCHAR(500),
                    ai_summary  TEXT,
                    tier        VARCHAR(10),
                    score       INT,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                INSERT INTO attack_logs
                    (detected_at, client_ip, country, uri, method, attack_type, parameters, ai_summary, tier, score)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score))
        conn.commit()
        conn.close()
        print(f"MySQL 저장 완료: {client_ip} | {rule_kor} | {tier} {score}점")
    except Exception as e:
        print(f"MySQL 저장 실패: {e}")

# ─────────────────────────────────────────────
# Correlation Rule
# ─────────────────────────────────────────────
def check_correlation(ip_groups: dict) -> dict:
    results = {}

    for client_ip, logs in ip_groups.items():
        alerts = []

        # MySQL에서 최근 5분간 같은 IP 차단 횟수 조회
        block_count = 0
        if PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
            try:
                conn = pymysql.connect(
                    host=os.environ.get('RDS_HOST'),
                    user=os.environ.get('RDS_USER'),
                    password=os.environ.get('RDS_PASSWORD'),
                    database=os.environ.get('RDS_DATABASE'),
                    connect_timeout=5,
                )
                with conn.cursor() as cursor:
                    # correlation_alerts 테이블 생성
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS correlation_alerts (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            client_ip VARCHAR(50),
                            tier VARCHAR(20),
                            alerted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    # ALTER TABLE 먼저
                    try:
                        cursor.execute("ALTER TABLE correlation_alerts ADD COLUMN tier VARCHAR(20)")
                    except:
                        pass
                    # 최근 5분 차단 횟수 조회
                    cursor.execute("""
                        SELECT COUNT(*) FROM attack_logs
                        WHERE client_ip = %s
                        AND created_at >= NOW() - INTERVAL 1 MINUTE
                    """, (client_ip,))
                    row = cursor.fetchone()
                    block_count = row[0] if row else 0
                conn.commit()
                conn.close()
                print(f"MySQL 조회 완료: {client_ip} | 최근 5분 {block_count}회")
            except Exception as e:
                print(f"MySQL 조회 실패: {e}")
                block_count = sum(1 for l in logs if l.get('action') == 'BLOCK')
        else:
            block_count = sum(1 for l in logs if l.get('action') == 'BLOCK')

        # 1. 브루트포스 탐지
        if block_count >= 8:
            alerts.append(("브루트포스 탐지", f"동일 IP {block_count}회 차단 — CRITICAL", "CRITICAL"))
        elif block_count >= 4:
            alerts.append(("브루트포스 탐지", f"동일 IP {block_count}회 차단 — WARNING", "WARNING"))

        # 2. 경로 탐색 탐지 — MySQL 누적 횟수 기반
        path_count = 0
        if PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
            try:
                conn = pymysql.connect(
                    host=os.environ.get('RDS_HOST'),
                    user=os.environ.get('RDS_USER'),
                    password=os.environ.get('RDS_PASSWORD'),
                    database=os.environ.get('RDS_DATABASE'),
                    connect_timeout=5,
                )
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT COUNT(*) FROM attack_logs
                        WHERE client_ip = %s
                        AND attack_type = '관리자 경로 접근 시도'
                        AND created_at >= NOW() - INTERVAL 1 MINUTE
                    """, (client_ip,))
                    row = cursor.fetchone()
                    path_count = row[0] if row else 0
                conn.close()
                print(f"경로 탐색 조회 완료: {client_ip} | 최근 5분 {path_count}회")
            except Exception as e:
                print(f"경로 탐색 조회 실패: {e}")

        if path_count >= 5:
            alerts.append(("경로 탐색 탐지", f"동일 IP {path_count}회 민감 경로 접근 — WARNING", "WARNING"))

        # 3. .env 스캐닝 탐지
        env_hits = [l for l in logs if '/.env' in l.get('httpRequest', {}).get('uri', '').lower()]
        if env_hits:
            alerts.append(("env 스캐닝 탐지", f"/.env GET 요청 {len(env_hits)}회 감지 — HIGH", "HIGH"))

        # 4. 다중 위치 로그인 탐지
        if PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
            try:
                conn = pymysql.connect(
                    host=os.environ.get('RDS_HOST'),
                    user=os.environ.get('RDS_USER'),
                    password=os.environ.get('RDS_PASSWORD'),
                    database=os.environ.get('RDS_DATABASE'),
                    connect_timeout=5,
                )
                with conn.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS login_logs (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(50),
                            ip VARCHAR(50),
                            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    cursor.execute("""
                        SELECT username, COUNT(DISTINCT ip) as ip_count
                        FROM login_logs
                        WHERE login_time >= NOW() - INTERVAL 5 MINUTE
                        GROUP BY username
                        HAVING ip_count >= 2
                    """)
                    multi_login = cursor.fetchall()
                    if multi_login:
                        for row in multi_login:
                            alerts.append(("다중 위치 로그인", f"{row[0]} 계정 {row[1]}개 IP에서 동시 접속 — CRITICAL", "CRITICAL"))
                conn.close()
            except Exception as e:
                print(f"다중 위치 로그인 탐지 실패: {e}")

        # 5.비정상 시간대 접근 탐지
        kst = timezone(timedelta(hours=9))
        current_hour = datetime.now(tz=kst).hour
        if 16 <= current_hour < 18:  # 테스트용: 16~18시
            kst_now = datetime.now(tz=kst)
            alerts.append(("비정상 시간대 접근", f"{kst_now.strftime('%H시 %M분')} 접근 탐지 — WARNING", "WARNING"))

        # 6.API Rate 탐지 — 5분 내 20회 이상
        if PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
            try:
                conn = pymysql.connect(
                    host=os.environ.get('RDS_HOST'),
                    user=os.environ.get('RDS_USER'),
                    password=os.environ.get('RDS_PASSWORD'),
                    database=os.environ.get('RDS_DATABASE'),
                    connect_timeout=5,
                )
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT COUNT(*) FROM attack_logs
                        WHERE client_ip = %s
                        AND created_at >= NOW() - INTERVAL 1 MINUTE
                    """, (client_ip,))
                    row = cursor.fetchone()
                    api_count = row[0] if row else 0
                conn.close()
                print(f"API Rate 조회 완료: {client_ip} | 최근 5분 {api_count}회")
                if api_count >= 3:
                    alerts.append(("API Rate 탐지", f"동일 IP {api_count}회 과도한 요청 — WARNING", "WARNING"))
            except Exception as e:
                print(f"API Rate 조회 실패: {e}")

        # 7. 다중 룰 트리거
        triggered_rules = set(l.get('terminatingRuleId', '') for l in logs if l.get('action') == 'BLOCK')
        if len(triggered_rules) >= 3:
            alerts.append(("다중 공격 패턴", f"{len(triggered_rules)}개 룰 동시 트리거 — CRITICAL", "CRITICAL"))

        if alerts:
            # 등급별 중복 알림 방지
            if PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
                try:
                    conn = pymysql.connect(
                        host=os.environ.get('RDS_HOST'),
                        user=os.environ.get('RDS_USER'),
                        password=os.environ.get('RDS_PASSWORD'),
                        database=os.environ.get('RDS_DATABASE'),
                        connect_timeout=5,
                    )
                    filtered_alerts = []
                    with conn.cursor() as cursor:
                        for alert in alerts:
                            tier = alert[2]
                            cursor.execute("""
                                SELECT COUNT(*) FROM correlation_alerts
                                WHERE client_ip = %s
                                AND tier = %s
                                AND alerted_at >= NOW() - INTERVAL 1 MINUTE
                            """, (client_ip, tier))
                            already = cursor.fetchone()[0]
                            if not already:
                                filtered_alerts.append(alert)
                    conn.commit()
                    conn.close()
                    alerts = filtered_alerts
                except Exception as e:
                    print(f"중복 알림 확인 실패: {e}")

            if alerts:
                results[client_ip] = alerts

    return results
# ─────────────────────────────────────────────
# Lambda 핸들러
# ─────────────────────────────────────────────
def lambda_handler(event, context):
    compressed = base64.b64decode(event['awslogs']['data'])
    log_data   = json.loads(gzip.decompress(compressed).decode('utf-8'))

    all_logs   = [json.loads(e['message']) for e in log_data['logEvents']]
    block_logs = [l for l in all_logs if l.get('action') == 'BLOCK']

    if not block_logs:
        return {'statusCode': 200, 'body': 'No BLOCK events'}

    ip_groups = {}
    for log in block_logs:
        ip = log.get('httpRequest', {}).get('clientIp', 'unknown')
        ip_groups.setdefault(ip, []).append(log)

    for client_ip, logs in ip_groups.items():
        risk  = compute_risk_score(logs, client_ip)
        tier  = risk['tier']
        score = risk['score']
        model = risk['model']

        print(f"[{tier}] IP: {client_ip} | Score: {score} | Rules: {list(risk['rule_counter'].keys())}")

        try:
            add_ip_to_blocklist(client_ip)
        except Exception as e:
            print(f"IP Set 추가 실패: {e}")

        rep      = max(logs, key=lambda l: RULE_WEIGHTS.get(l.get('terminatingRuleId', ''), 0))
        kst      = timezone(timedelta(hours=9))
        dt       = datetime.fromtimestamp(rep.get('timestamp', 0) / 1000, tz=kst)
        time_str = dt.strftime("%Y년 %m월 %d일 %H시 %M분 %S초")
        http     = rep.get('httpRequest', {})
        country  = http.get('country',    '알 수 없음')
        uri      = http.get('uri',        '알 수 없음')
        method   = http.get('httpMethod', '알 수 없음')
        args     = http.get('args',       '없음')
        rule     = rep.get('terminatingRuleId', '알 수 없음')
        rule_kor = RULE_MAP.get(rule, rule)

        if tier == 'LOW':
            save_to_mysql(time_str, client_ip, country, uri, method, rule_kor, args, '', tier, score)
            save_to_opensearch(time_str, client_ip, country, uri, method, rule_kor, args, '', tier, score)
            continue

        # 1단계: MySQL 저장
        save_to_mysql(time_str, client_ip, country, uri, method, rule_kor, args, '', tier, score)
        save_to_opensearch(time_str, client_ip, country, uri, method, rule_kor, args, '', tier, score)

    # 2단계: Correlation Rule 체크 (for 루프 밖에서 한 번만 실행)
    correlation_results = check_correlation(ip_groups)

    for client_ip, logs in ip_groups.items():
        risk  = compute_risk_score(logs, client_ip)
        tier  = risk['tier']
        score = risk['score']
        model = risk['model']

        rep      = max(logs, key=lambda l: RULE_WEIGHTS.get(l.get('terminatingRuleId', ''), 0))
        kst      = timezone(timedelta(hours=9))
        dt       = datetime.fromtimestamp(rep.get('timestamp', 0) / 1000, tz=kst)
        time_str = dt.strftime("%Y년 %m월 %d일 %H시 %M분 %S초")
        http     = rep.get('httpRequest', {})
        country  = http.get('country',    '알 수 없음')
        uri      = http.get('uri',        '알 수 없음')
        method   = http.get('httpMethod', '알 수 없음')
        args     = http.get('args',       '없음')
        rule     = rep.get('terminatingRuleId', '알 수 없음')
        rule_kor = RULE_MAP.get(rule, rule)

        if tier == 'LOW':
            continue

        corr_alerts = correlation_results.get(client_ip, []) if correlation_results else []

        # 3단계: LLM 분석
        try:
            summary = ask_llama(
                client_ip, country, uri, method, rule_kor, args, model, tier,
                rule_counter=risk['rule_counter'], score=score,
                correlation_alerts=corr_alerts if corr_alerts else None,
            )
        except Exception as e:
            summary = f"LLM 분석 실패: {e}"

        # MySQL summary 업데이트
        if PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
            try:
                conn = pymysql.connect(
                    host=os.environ.get('RDS_HOST'),
                    user=os.environ.get('RDS_USER'),
                    password=os.environ.get('RDS_PASSWORD'),
                    database=os.environ.get('RDS_DATABASE'),
                    connect_timeout=5,
                )
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE attack_logs SET ai_summary = %s
                        WHERE client_ip = %s
                        ORDER BY created_at DESC LIMIT 1
                    """, (summary, client_ip))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"MySQL summary 업데이트 실패: {e}")

        # 4단계: 알림 전송
        try:
            send_email(time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score,
                       model_id=model, correlation_alerts=corr_alerts if corr_alerts else None)
        except Exception as e:
            print(f"이메일 알림 실패: {e}")

        try:
            send_discord(time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score,
                         model_id=model, correlation_alerts=corr_alerts if corr_alerts else None)
        except Exception as e:
            print(f"Discord 알림 실패: {e}")

        # Correlation 알림 기록 저장
        if corr_alerts and PYMYSQL_AVAILABLE and os.environ.get('RDS_HOST'):
            try:
                conn = pymysql.connect(
                    host=os.environ.get('RDS_HOST'),
                    user=os.environ.get('RDS_USER'),
                    password=os.environ.get('RDS_PASSWORD'),
                    database=os.environ.get('RDS_DATABASE'),
                    connect_timeout=5,
                )
                with conn.cursor() as cursor:
                    for alert in corr_alerts:
                        cursor.execute("""
                            INSERT INTO correlation_alerts (client_ip, tier)
                            VALUES (%s, %s)
                        """, (client_ip, alert[2]))
                conn.commit()
                conn.close()
                print(f"Correlation 알림 기록 저장 완료: {client_ip}")
            except Exception as e:
                print(f"Correlation 알림 기록 저장 실패: {e}")

    return {'statusCode': 200}
# ─────────────────────────────────────────────
# AbuseIPDB API 연동
# ─────────────────────────────────────────────
def check_abuseipdb(ip):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": os.environ.get('ABUSEIPDB_API_KEY'),
                "Accept": "application/json"
            },
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )
        result = response.json()
        if "data" not in result:
            print(f"AbuseIPDB 응답 오류: {result}")
            return 0
        score = result["data"]["abuseConfidenceScore"]
        print(f"AbuseIPDB 조회 완료: {ip} | 점수: {score}")
        return score
    except Exception as e:
        print(f"AbuseIPDB 조회 실패: {e}")
        return 0;
# ─────────────────────────────────────────────
# AlienVault OTX API 연동
# ─────────────────────────────────────────────
def check_otx(ip):
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": os.environ.get('OTX_API_KEY')}
        )
        data = response.json()
        pulse_count = data.get('pulse_info', {}).get('count', 0)
        print(f"OTX 조회 완료: {ip} | pulse 수: {pulse_count}")
        return pulse_count  # 위협 보고서 수
    except Exception as e:
        print(f"OTX 조회 실패: {e}")
        return 0
# ─────────────────────────────────────────────
# OpenSearch 저장
# ─────────────────────────────────────────────
def save_to_opensearch(time_str, client_ip, country, uri, method, rule_kor, args, summary, tier, score):
    try:
        endpoint = os.environ.get('OPENSEARCH_ENDPOINT')
        username = os.environ.get('OPENSEARCH_USERNAME')
        password = os.environ.get('OPENSEARCH_PASSWORD')

        doc = {
            # 정규화 표준 필드 추가
            "@timestamp":  datetime.now(timezone.utc).isoformat(),
            "severity":    tier,
            "src_ip":      client_ip,
            # 기존 필드 유지
            "detected_at": time_str,
            "client_ip":   client_ip,
            "country":     country,
            "uri":         uri,
            "method":      method,
            "attack_type": rule_kor,
            "parameters":  args,
            "ai_summary":  summary,
            "tier":        tier,
            "score":       score,
            "source":      "WAF"
        }
        response = requests.post(
            f"{endpoint}/waf-logs/_doc",
            auth=(username, password),
            headers={"Content-Type": "application/json"},
            json=doc
        )
        print(f"OpenSearch 저장 완료: {response.status_code}")
    except Exception as e:
        print(f"OpenSearch 저장 실패: {e}")

# ─────────────────────────────────────────────
# EC2 로그 정규화
# ─────────────────────────────────────────────
def normalize_ec2(raw):
    severity_map = {
        "ERROR": "CRITICAL", "WARNING": "WARNING",
        "INFO": "LOW", "CRITICAL": "CRITICAL"
    }
    level = raw.get("level", "INFO").upper()

    doc = {
        "@timestamp": datetime.fromisoformat(
            raw.get("timestamp")
        ).astimezone(timezone.utc).isoformat(),
        "severity":    severity_map.get(level, "LOW"),
        "source":      "EC2",
        "src_ip":      raw.get("src_ip"),
        "action":      raw.get("event_type"),
        "rule_id":     None,
        "request_uri": None,
        "country":     None,
        "user_id":     raw.get("user_id"),
        "host":        raw.get("hostname"),
    }

    endpoint = os.environ.get('OPENSEARCH_ENDPOINT')
    username = os.environ.get('OPENSEARCH_USERNAME')
    password = os.environ.get('OPENSEARCH_PASSWORD')

    try:
        response = requests.post(
            f"{endpoint}/ec2-logs/_doc",
            auth=(username, password),
            headers={"Content-Type": "application/json"},
            json=doc
        )
        print(f"EC2 OpenSearch 저장 완료: {response.status_code}")
    except Exception as e:
        print(f"EC2 OpenSearch 저장 실패: {e}")

    return doc


# ─────────────────────────────────────────────
# CloudTrail 로그 정규화
# ─────────────────────────────────────────────
def normalize_cloudtrail(raw):
    event_name = raw.get("eventName", "")

    high_risk_events = {
        "DeleteLogGroup", "PutBucketPolicy",
        "CreateUser", "AttachUserPolicy",
        "DeleteTrail", "StopLogging"
    }
    severity = "CRITICAL" if event_name in high_risk_events else "LOW"

    doc = {
        "@timestamp": datetime.strptime(
            raw["eventTime"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc).isoformat(),
        "severity":    severity,
        "source":      "CloudTrail",
        "src_ip":      raw.get("sourceIPAddress"),
        "action":      event_name,
        "rule_id":     None,
        "request_uri": None,
        "country":     None,
        "user_id":     raw.get("userIdentity", {}).get("userName"),
        "aws_region":  raw.get("awsRegion"),
    }

    endpoint = os.environ.get('OPENSEARCH_ENDPOINT')
    username = os.environ.get('OPENSEARCH_USERNAME')
    password = os.environ.get('OPENSEARCH_PASSWORD')

    try:
        response = requests.post(
            f"{endpoint}/cloudtrail-logs/_doc",
            auth=(username, password),
            headers={"Content-Type": "application/json"},
            json=doc
        )
        print(f"CloudTrail OpenSearch 저장 완료: {response.status_code}")
    except Exception as e:
        print(f"CloudTrail OpenSearch 저장 실패: {e}")

    return doc