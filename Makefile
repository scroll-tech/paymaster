.PHONY: lint fmt build docker
.DEFAULT_GOAL := build

IMAGE_VERSION=latest

lint:
	GOBIN=$(PWD)/build/bin go run ./build/lint.go

fmt:
	go mod tidy
	goimports -w .
	gofumpt -l -w .

build:
	go build -o $(PWD)/build/bin/paymaster ./cmd/

docker:
	docker build --platform linux/amd64 -t scrolltech/paymaster:${IMAGE_VERSION} ./ -f ./build/paymaster.Dockerfile
