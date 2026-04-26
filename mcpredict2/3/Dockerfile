# syntax=docker/dockerfile:1

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git (needed for go mod download with VCS)
RUN apk add --no-cache git

COPY . .
# go mod tidy generates go.sum and fetches all dependencies.
RUN GONOSUMDB="*" go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/mcpredict ./cmd/mcpredict/

# ── Stage 2: Test (stays in builder for toolchain access) ───────────────────
FROM builder AS tester
RUN go test -v -count=1 ./...

# ── Stage 3: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20 AS runtime

RUN apk add --no-cache jq bash

COPY --from=builder /bin/mcpredict /usr/local/bin/mcpredict
COPY examples/ /examples/

RUN chmod +x /examples/test_all.sh

# 정책 디렉터리만 생성 — 룰 파일은 런타임에 마운트하거나 직접 추가
# ~/.mcpredict/policies/*.yaml 변경 시 재시작·재빌드 없이 즉시 반영됨
RUN mkdir -p /root/.mcpredict/policies /root/.mcpredict/sessions

ENV MCPREDICT_HOME=/root/.mcpredict

ENTRYPOINT ["mcpredict"]
CMD ["version"]
