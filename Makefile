export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

TARGET_HOST ?= "undefined"
TARGET_DIR ?= ~/tracker

GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
PYTHON_VERSION ?= 3.11
REGISTRY ?= ghcr.io
REPOSITORY ?= hostmaster/crypto-wallet-tracker

.PHONY: all build push deploy docker-login test dev clean

all: build

build: docker-bake.hcl Dockerfile
	docker buildx bake

build-dev: docker-bake.hcl Dockerfile
	docker buildx bake dev

test: docker-bake.hcl Dockerfile
	docker buildx bake test

push: build docker-login
	docker buildx bake --push

dev:
	docker compose up dev

sync: docker-compose.yml
	rsync -va -z docker-compose.yml docker-bake.hcl $(TARGET_HOST):$(TARGET_DIR)/

deploy: sync
	ssh $(TARGET_HOST) "cd $(TARGET_DIR) && \
		GIT_COMMIT=$(GIT_COMMIT) \
		PYTHON_VERSION=$(PYTHON_VERSION) \
		REGISTRY=$(REGISTRY) \
		REPOSITORY=$(REPOSITORY) \
		docker buildx bake --push runtime"

docker-login:
	@echo "Logging in to $(REGISTRY)"
	@echo ${CR_PAT} | docker login $(REGISTRY) -u $(DOCKER_USER) --password-stdin

clean:
	docker compose down -v
	docker buildx prune -f
