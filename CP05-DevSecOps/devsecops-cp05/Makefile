IMAGE ?= cp05-site:local

.PHONY: sabotage build scan run
sabotage:
	python3 scripts/prove_sabotage.py

build:
	podman build --pull -t $(IMAGE) .

scan:
	trivy image --severity CRITICAL --exit-code 1 $(IMAGE)

run:
	podman run --rm -p 8080:8080 $(IMAGE)
