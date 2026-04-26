# Gitleaks 정규식 서브셋 (mcpredict embed용)

> 출처: zricethezav/gitleaks rules.toml (시나리오 2·DLP scanner 입력)
> 채택 기준: 자주 누출되는 자격증명, 정규식 명확, false positive 낮음. 5~10개 우선.
> Go embed: `//go:embed patterns/gitleaks-subset.json` 으로 정적 포함 예정.

## 패턴 (정규식은 Go RE2 호환)

| ID | 설명 | 정규식 (RE2) | 엔트로피 임계 |
|---|---|---|---|
| `aws-access-key-id` | AWS Access Key ID | `\bAKIA[0-9A-Z]{16}\b` | - |
| `aws-secret-access-key` | AWS Secret Access Key | `\b[A-Za-z0-9/+=]{40}\b` | ≥4.5 (high) |
| `github-pat` | GitHub Personal Access Token | `\bghp_[0-9A-Za-z]{36}\b` | - |
| `github-oauth` | GitHub OAuth Token | `\bgho_[0-9A-Za-z]{36}\b` | - |
| `github-app` | GitHub App Token | `\b(ghu|ghs)_[0-9A-Za-z]{36}\b` | - |
| `slack-bot-token` | Slack Bot Token | `\bxoxb-[0-9]+-[0-9]+-[0-9a-zA-Z]+\b` | - |
| `private-key-pem` | PEM private key 헤더 | `-----BEGIN (RSA \|EC \|OPENSSH \|DSA \|)PRIVATE KEY-----` | - |
| `openai-api-key` | OpenAI API Key | `\bsk-[A-Za-z0-9]{20,}\b` | - |
| `anthropic-api-key` | Anthropic API Key | `\bsk-ant-[A-Za-z0-9_-]{50,}\b` | - |
| `stripe-secret` | Stripe Secret Key | `\b(sk\|rk)_(live\|test)_[0-9A-Za-z]{20,}\b` | - |
| `generic-high-entropy` | 일반 고엔트로피 토큰 (32자+ base64ish) | `\b[A-Za-z0-9+/=_-]{32,}\b` | ≥4.5 |

## 매처 동작 의사 코드

```go
// internal/scanner
type Hit struct {
    PatternID  string
    MatchStart int
    MatchEnd   int
    Excerpt    string  // 최대 32자, 앞 8자 + "***" + 뒤 8자
}

func Scan(text string) []Hit {
    if len(text) > MaxScanBytes { // 1MB cap (regex DoS 방지)
        text = text[:MaxScanBytes]
    }
    var hits []Hit
    for _, p := range patterns {
        for _, loc := range p.Regex.FindAllStringIndex(text, -1) {
            if p.EntropyMin > 0 {
                if shannonEntropy(text[loc[0]:loc[1]]) < p.EntropyMin { continue }
            }
            hits = append(hits, Hit{...})
        }
    }
    return hits
}
```

## 엔트로피 정규식 보조

`generic-high-entropy`는 false positive 폭발 위험 → 엔트로피 임계로 필터.
shannonEntropy(s) = -Σ p(c) log2 p(c). base64 분포는 ≥4.5 일반.

## False positive 우려 케이스

- `aws-secret-access-key`의 40자 base64 패턴은 Git SHA-256 hex(40자)와 형태 충돌 가능 — 엔트로피로 분리.
- `generic-high-entropy`는 테스트 환경 fixture·UUID 등에 발화 — 정책에서 `Bash` `WebFetch` 외엔 warn으로만.

## 향후 추가 (시간 되면)

- Google Cloud Service Account JSON
- Heroku API Key
- Mailgun Token
- JWT 헤더 패턴 (`eyJ[A-Za-z0-9-_]+\.eyJ...`)
