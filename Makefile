#!/usr/bin/make -f

.ONESHELL:
.SHELL := /usr/bin/bash

PROJECTNAME := $(shell basename "$$(pwd)")
PROJECTPATH := $(shell pwd)

help:
	echo "Usage: make [options] [arguments]\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

go-build: ## Compiles packages and dependencies. Builds a binary for the api service under bin/. *Accepts flags
	@[ -d bin ] || mkdir bin
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build $(LDFLAGS) -o bin/ "$(PROJECTPATH)/cmd/..."

go-run: ## Starts API project. *Accepts flags
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go run $(LDFLAGS) "$(PROJECTPATH)/cmd/api/main.go"

go-doc: ## Generates static docs
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) godoc -http=localhost:6060

go-vendor: ## Updates vendor dependencies
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go get ./... && go mod tidy && go mod vendor

test: ## Runs the tests
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test ./...

docker-build: ## Builds the project binary inside a docker image
	docker build -t $(PROJECTNAME) .

docker-run:	## Runs the previosly build docker image
	@docker run $(PROJECTNAME) -p 8080:8080

compose-mac: ## Starts docker-compose project for a Mac OS (Darwin arch)
	docker-compose up -d zipkin postgres
	TRACE_URL=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' zipkin) ;\
	docker-compose --file "$(PROJECTPATH)/docker-compose.yaml" run --service-ports -e ENV_ARGS="--database-host=docker.for.mac.localhost --trace-url=http://$$TRACE_URL:9411/api/v2/spans" goauthsvc

compose-linux: ## Starts docker-compose project for a Linux OS
	docker-compose up -d zipkin postgres
	docker-compose --file "$(PROJECTPATH)/docker-compose.yaml" --verbose up goauthsvc
