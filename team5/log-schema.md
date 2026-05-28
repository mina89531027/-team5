# 로그 정규화 스키마 설계

> 작성일: 2026-05-28  
> 담당: 파트 A (OpenSearch & 대시보드)  
> 목적: WAF · EC2 · CloudTrail 로그를 공통 스키마로 통일하여 OpenSearch 인덱싱 및 탐지 규칙 적용

---

## 1. 공통 스키마 (Normalized Schema)

모든 로그는 수집 후 아래 형식으로 변환되어 OpenSearch에 저장됩니다.

```json
{
  "timestamp":  "2026-05-28T09:23:11Z",
  "severity":   "HIGH",
  "source":     "WAF",
  "src_ip":     "1.2.3.4",
  "dst_ip":     "10.0.0.1",
  "action":     "BLOCK",
  "message":    "WAF BLOCK - /admin login attempt from 1.2.3.4",
  "raw":        {}
}
```

### 필드 정의

| 필드 | 타입 | 설명 | 예시 |
|---|---|---|---|
| `timestamp` | string (ISO 8601) | 이벤트 발생 시각 (UTC 통일) | `2026-05-28T09:23:11Z` |
| `severity` | string (ENUM) | 심각도 (LOW / MEDIUM / HIGH / CRITICAL) | `HIGH` |
| `source` | string (ENUM) | 로그 출처 | `WAF` / `EC2` / `CloudTrail` |
| `src_ip` | string (IP) | 출발지 IP | `1.2.3.4` |
| `dst_ip` | string (IP) | 목적지 IP (없으면 null) | `10.0.0.1` |
| `action` | string | 수행된 액션 | `BLOCK` / `ALLOW` / `REJECT` |
| `message` | string | 사람이 읽을 수 있는 요약 | `WAF BLOCK - SQL injection` |
| `raw` | object | 원본 로그 전체 보존 | `{ ...원본 필드 }` |

---

## 2. 소스별 필드 매핑

### 2-1. WAF 로그

**원본 주요 필드:** `timestamp`, `action`, `clientIp`, `httpRequest.uri`, `httpRequest.httpMethod`

| 공통 필드 | WAF 원본 필드 | 변환 규칙 |
|---|---|---|
| `timestamp` | `timestamp` | Unix ms → ISO 8601 변환 |
| `severity` | `action` + 룰 매칭 여부 | 아래 severity 판단 기준 참고 |
| `source` | 없음 | `"WAF"` 고정값 |
| `src_ip` | `clientIp` | 그대로 사용 |
| `dst_ip` | 없음 | `null` |
| `action` | `action` | ALLOW / BLOCK / CAPTCHA / CHALLENGE |
| `message` | `httpRequest.uri` + `action` | `"WAF {action} - {uri}"` 형식으로 생성 |

**WAF 원본 샘플:**
```json
{
  "timestamp": 1716887391000,
  "action": "BLOCK",
  "clientIp": "1.2.3.4",
  "country": "CN",
  "httpRequest": {
    "uri": "/admin",
    "httpMethod": "POST",
    "httpVersion": "HTTP/1.1"
  }
}
```

---

### 2-2. EC2 로그 (VPC Flow Logs)

**원본 주요 필드:** `start`, `srcaddr`, `dstaddr`, `srcport`, `dstport`, `action`

| 공통 필드 | EC2 원본 필드 | 변환 규칙 |
|---|---|---|
| `timestamp` | `start` | Unix 초 → ISO 8601 변환 |
| `severity` | `action` + 반복 횟수 | 아래 severity 판단 기준 참고 |
| `source` | 없음 | `"EC2"` 고정값 |
| `src_ip` | `srcaddr` | 그대로 사용 |
| `dst_ip` | `dstaddr` | 그대로 사용 |
| `action` | `action` | ACCEPT / REJECT |
| `message` | `srcaddr` + `dstaddr` + `action` | `"EC2 {action} - {srcaddr} → {dstaddr}:{dstport}"` |

**EC2 원본 샘플:**
```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-abc123 1.2.3.4 10.0.0.1 443 8080 6 10 840 1716887391 1716887451 REJECT OK
```

---

### 2-3. CloudTrail 로그

**원본 주요 필드:** `eventTime`, `eventName`, `eventSource`, `sourceIPAddress`, `userIdentity`

| 공통 필드 | CloudTrail 원본 필드 | 변환 규칙 |
|---|---|---|
| `timestamp` | `eventTime` | ISO 8601 형식 그대로 사용 |
| `severity` | `eventName` 기준 | 아래 severity 판단 기준 참고 |
| `source` | 없음 | `"CloudTrail"` 고정값 |
| `src_ip` | `sourceIPAddress` | 그대로 사용 |
| `dst_ip` | 없음 | `null` |
| `action` | `eventName` | 원본 그대로 사용 (ex. `ConsoleLogin`) |
| `message` | `eventName` + `eventSource` | `"CloudTrail {eventName} - {eventSource}"` |

**CloudTrail 원본 샘플:**
```json
{
  "eventTime": "2026-05-28T09:23:11Z",
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "sourceIPAddress": "1.2.3.4",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "admin"
  }
}
```

---

## 3. Severity 판단 기준

원본 로그에 severity 필드가 없으므로, 아래 규칙으로 변환 시 자동 부여합니다.

| severity | WAF | EC2 (VPC Flow) | CloudTrail |
|---|---|---|---|
| `CRITICAL` | BLOCK + 알려진 공격 룰 매칭 (SQLi, XSS 등) | REJECT 5회 이상 반복 (동일 IP) | 루트 계정 로그인 |
| `HIGH` | BLOCK (일반) | REJECT (단발) | IAM 정책 변경, 콘솔 로그인 실패 |
| `MEDIUM` | ALLOW + 룰 매칭 (COUNT 모드) | 비정상 포트 접근 (22, 3389 등) | 리소스 삭제 이벤트 |
| `LOW` | ALLOW (정상 트래픽) | ACCEPT (정상 트래픽) | 일반 API 호출 |

---

## 4. OpenSearch 인덱스 구조

| 인덱스명 | 대상 로그 | 보존 기간 |
|---|---|---|
| `logs-waf` | WAF 로그 | 90일 |
| `logs-ec2` | VPC Flow Logs | 90일 |
| `logs-cloudtrail` | CloudTrail 로그 | 180일 |
| `ioc-feeds` | 외부 위협 피드 (AbuseIPDB, OTX) | 상시 |

---

## 5. 변경 이력

| 날짜 | 내용 | 작성자 |
|---|---|---|
| 2026-05-28 | 최초 작성 | 파트 A |
