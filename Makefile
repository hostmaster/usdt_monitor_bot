
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

TARGET_HOST ?= "undefined"
TARGET_DIR ?= ~/tracker

.PHONY: all build push deploy docker-login

all: build

build: Dockerfile *.py
	 docker compose build

push: build docker-login
	docker compose push

sync: docker-compose.yml
	rsync -va -z docker-compose.yml $(TARGET_HOST):$(TARGET_DIR)/docker-compose.yml

deploy: sync
	ssh $(TARGET_HOST) "cd $(TARGET_DIR) && docker compose up --pull=always --detach --no-build"

docker-login:
	@echo "Logging in to ghcr.io"
	@echo ${CR_PAT} | docker login ghcr.io -u USERNAME --password-stdin
