# Bypass Catalog — mcpredict v1.0 우회 패턴 14종 + Unicode

> `internal/scanner/bypass.go`에서 RE2 regex로 탐지. 매 PreToolUse마다 `tool_input` 직렬화 문자열에 대해 평가됨. 매치 시 `verdict.Deny + Source:"bypass"`.
>
> Unicode 우회는 별도 `ScanUnicodeBypass` — `verdict.Warn` (FP 위험으로 강제 차단 대신 경고).

---

## 1. Interpreter Sandbox Escape (4종)

LLM이 Bash 직접 호출 대신 Python·Perl·Node·Ruby의 `-c/-e` 플래그를 빌려 셸 명령을 우회 실행하는 패턴.

| 패턴 | regex 핵심 | 예시 |
|---|---|---|
| `python-shell-escape` | `python[23]?\s+-c\s+...(import os\|exec\|__import__\|subprocess\|pty)` | `python3 -c 'import subprocess; subprocess.run(["sh"])'` |
| `perl-shell-escape` | `perl\s+-e\s+...(system\|exec\|open\(...\|)` | `perl -e 'system("rm -rf /")'` |
| `node-shell-escape` | `node\s+(-e\|-p)\s+...(require\(['"]child_process\|exec\|spawn)` | `node -e 'require("child_process").exec("...")'` |
| `ruby-shell-escape` | `ruby\s+-e\s+...(\`\|system\|exec\|IO.popen)` | `ruby -e 'system("...")'` |

> "Bash가 아니니까" 정책 룰을 우회. 항상 차단.

---

## 2. Encoding Obfuscation (3종)

명령 본문을 base64·hex로 감춰 keyword 매칭을 회피하는 패턴.

| 패턴 | regex 핵심 | 예시 |
|---|---|---|
| `base64-pipe-exec` | `(echo BASE64\|base64 -d) ... \| (sh\|bash\|zsh\|fish)` | `echo Y3VybCAuLi4gfCBzaA== \| base64 -d \| sh` |
| `base64-herestring-exec` | `base64 (-d\|--decode) <<< BASE64` | `base64 -d <<< Y3VybCAuLi4=` |
| `xxd-decode-exec` | `xxd (-r\|-revert) ... \| (sh\|bash\|zsh)` | `xxd -r <hex> \| bash` |

---

## 3. Shell Metacharacter Bypass (3종)

키워드 사이 공백·따옴표·변수를 끼워 substring 매칭을 무력화.

| 패턴 | regex 핵심 | 예시 |
|---|---|---|
| `ifs-bypass` | `\$\{?IFS\}?` | `cat${IFS}/etc/passwd` |
| `ansi-c-hex-escape` | `\$'(\\x[0-9a-fA-F]{2}\|\\[0-7]{1,3}){3,}'` | `$'\x62\x61\x73\x68'` (= "bash") |
| `string-concat-bypass` | `\bb['"\$]?[a-z'"\$]?['"\$]?s[h'"\$]\b` | `ba''sh`, `b"a"sh`, `b$@ash`, `b${x}ash` |

---

## 4. Privilege Escalation Path (2종)

| 패턴 | regex 핵심 | 예시 |
|---|---|---|
| `env-exec-bypass` | `\benv\b(\s+-\w+)*\s+(sh\|bash\|zsh\|python\|perl\|node\|ruby)\b` | `env -i bash -c "..."` |
| `path-traversal-cmd` | `/{2,}(bin\|sh\|bash)\|/\w+/\.\./+\w*(sh\|bash)` | `///bin/bash`, `/usr/../bin/bash` |

---

## 5. Download-Then-Execute (2종)

curl/wget으로 받아서 별개 명령으로 실행하는 패턴 (단순 `curl \| sh`보다 한 단계 우회).

| 패턴 | regex 핵심 | 예시 |
|---|---|---|
| `download-then-execute` | `(curl\|wget) ... -o FILE ... [;&\n] (chmod\|bash\|sh\|./)` | `curl -o /tmp/x ...; chmod +x /tmp/x; /tmp/x` |
| `tmpfile-exec` | `/tmp/FILE ... [;&\n] ... chmod \| chmod ... /tmp/FILE` | `/tmp/payload; chmod +x /tmp/payload` |

---

## 6. File Descriptor Hijack (1종)

| 패턴 | regex 핵심 | 예시 |
|---|---|---|
| `exec-fd-hijack` | `\bexec\s+[0-9]+[<>][&]?[0-9]` | `exec 3>&1; ...; exec 3<&-` (TCP backdoor) |

---

## 7. Unicode Bypass (별도 — Warn 등급)

LLM이 Cyrillic 동형자(homoglyph) 또는 zero-width 문자를 끼워 ASCII 키워드 매칭을 회피하는 패턴.

### 7.1 Cyrillic Homoglyph
```go
[\x{0406}\x{0456}\x{0410}\x{0430}\x{0412}\x{0432}
 \x{0435}\x{043E}\x{0440}\x{0441}\x{0443}\x{04BB}\x{0581}]
```
- I·і·А·а·В·в·е·о·р·с·у·һ·ց — Latin lookalike
- 예: `ìgnore` (i+Cyrillic ì), `іnstructіons` (i+Cyrillic і·і)

### 7.2 Zero-Width Characters
```go
[\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}
 \x{FEFF}\x{2060}\x{2061}\x{2062}\x{2063}]
```
- ZWSP·ZWNJ·ZWJ·LRM·RLM·BOM·WJ — invisible
- 예: `i​gnore` — substring `ignore`로 보이지만 `​`가 끼어 있어 `strings.Contains("ignore")` 실패

> Unicode hits는 prompt-injection 또는 keyword evasion의 강한 신호. 다만 multilingual code/comment에 정상 등장 가능 → `Warn` 등급으로 사용자 확인 유도.

---

## 8. 우회 패턴 발견 → 추가 가이드

새 우회 패턴을 발견했을 때:

1. `internal/scanner/bypass.go`의 `bashBypassPatterns` slice에 한 줄 추가
2. `internal/scanner/bypass_test.go`에 positive + negative 케이스 추가 (FP 회귀 방지)
3. 본 카탈로그에 카테고리 + regex 핵심 + 예시 명시
4. 정책 측에서 별도 차단이 필요하면 `examples/policies/bypass-extended.yaml`에도 등록

---

## 9. 통계 (현재)

| 카테고리 | 패턴 수 |
|---|---|
| Interpreter Escape | 4 |
| Encoding Obfuscation | 3 |
| Shell Metacharacter | 3 |
| Privilege Escalation Path | 2 |
| Download-Then-Execute | 2 |
| File Descriptor Hijack | 1 |
| **Bash 합계** | **15** |
| Unicode (Cyrillic + zero-width) | 2 (별도 함수) |

> regex로 잡히지 않는 카테고리(`base64 obfuscation에 대한 의미적 추적`, `embedding 기반 의미 정합성`)는 SPEC §9의 알려진 한계로 명시. 미래 보강.
