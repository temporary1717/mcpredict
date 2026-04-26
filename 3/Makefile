IMAGE := mcpredict:dev

.PHONY: build test-unit test-integration test demo \
        scenario1 scenario2 scenario3 scenario4 scenario5 scenario6 \
        dashboard install install-auto install-manual clean cleanup

## build — build Docker image (all stages including unit tests)
build:
	docker build -t $(IMAGE) .

## test-unit — run Go unit tests (executed during docker build tester stage)
test-unit: build

## test-integration — run all 6 scenario integration tests
test-integration: build
	docker run --rm --entrypoint sh \
		-e MCPREDICT_HOME=/tmp/.mcpredict \
		$(IMAGE) /examples/test_all.sh

## test — run unit tests (via build) then integration tests
test: test-integration

## demo — run all scenarios sequentially (visual output)
demo: build
	@echo ""
	@echo "=== Scenario 1: Intent Mismatch ==="
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    mcpredict pre < /examples/fixtures/scenario1_intent_mismatch.json; echo exit: $$?" || true
	@echo ""
	@echo "=== Scenario 2: Credential Exfiltration ==="
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    mcpredict pre < /examples/fixtures/scenario2_credential_exfil.json; echo exit: $$?" || true
	@echo ""
	@echo "=== Scenario 3: Prompt Injection ==="
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    mcpredict post < /examples/fixtures/scenario3_prompt_injection.json; echo exit: $$?" || true
	@echo ""
	@echo "=== Scenario 4: Safe Pass-through ==="
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    mcpredict pre < /examples/fixtures/scenario4_safe_passthrough.json; echo exit: $$?" || true
	@echo ""
	@echo "=== Scenario 5: Base64 Bypass ==="
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    mcpredict pre < /examples/fixtures/scenario5_bypass_base64.json; echo exit: $$?" || true
	@echo ""
	@echo "=== Scenario 6: Python Shell Escape Bypass ==="
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    mcpredict pre < /examples/fixtures/scenario6_bypass_python.json; echo exit: $$?" || true

## scenario1-6 — run a single scenario
scenario1: build
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '=== Scenario 1: Intent Mismatch ===' && \
		    mcpredict pre < /examples/fixtures/scenario1_intent_mismatch.json; echo exit: $$?" || true

scenario2: build
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '=== Scenario 2: Credential Exfiltration ===' && \
		    mcpredict pre < /examples/fixtures/scenario2_credential_exfil.json; echo exit: $$?" || true

scenario3: build
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '=== Scenario 3: Prompt Injection ===' && \
		    mcpredict post < /examples/fixtures/scenario3_prompt_injection.json; echo exit: $$?" || true

scenario4: build
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '=== Scenario 4: Safe Pass-through ===' && \
		    mcpredict pre < /examples/fixtures/scenario4_safe_passthrough.json; echo exit: $$?" || true

scenario5: build
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '=== Scenario 5: Base64 Bypass ===' && \
		    mcpredict pre < /examples/fixtures/scenario5_bypass_base64.json; echo exit: $$?" || true

scenario6: build
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '=== Scenario 6: Python Shell Escape Bypass ===' && \
		    mcpredict pre < /examples/fixtures/scenario6_bypass_python.json; echo exit: $$?" || true

## dashboard — seed demo events and start web dashboard on http://localhost:8080
dashboard: build
	@echo ""
	@echo "  Dashboard: http://localhost:8080"
	@echo "  Press Ctrl+C to stop."
	@echo ""
	docker run --rm --entrypoint sh -e MCPREDICT_HOME=/tmp/.mcpredict -p 8080:8080 $(IMAGE) \
		-c "mkdir -p /tmp/.mcpredict/policies /tmp/.mcpredict/sessions && \
		    cp /examples/policies/default.yaml /tmp/.mcpredict/policies/ && \
		    echo '--- seeding audit log ---' && \
		    mcpredict pre  < /examples/fixtures/scenario1_intent_mismatch.json; true && \
		    mcpredict pre  < /examples/fixtures/scenario2_credential_exfil.json; true && \
		    mcpredict post < /examples/fixtures/scenario3_prompt_injection.json; true && \
		    mcpredict pre  < /examples/fixtures/scenario4_safe_passthrough.json; true && \
		    mcpredict pre  < /examples/fixtures/scenario5_bypass_base64.json;    true && \
		    mcpredict pre  < /examples/fixtures/scenario6_bypass_python.json;    true && \
		    echo '--- starting dashboard ---' && \
		    mcpredict dashboard 8080"

## install — 대화형 설치 (변경 내용 확인 후 Y/N)
install:
	@bash install.sh

## install-auto — 자동 설치 (확인 없이 즉시 settings.json 수정)
install-auto:
	@bash install.sh --auto

## install-manual — 바이너리만 설치 + 수동 설정 가이드 출력
install-manual:
	@bash install.sh --manual

## clean — remove Docker image
clean:
	docker rmi $(IMAGE) 2>/dev/null || true

## cleanup — 완전 원상복구 (바이너리 + hook 설정 + 감사 데이터 + Docker 이미지)
cleanup:
	@bash cleanup.sh
