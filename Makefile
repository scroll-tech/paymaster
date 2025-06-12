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

test:
	go test -v -race -coverprofile=coverage.out ./...

docker:
	docker build --platform linux/amd64 -t scrolltech/paymaster:${IMAGE_VERSION} ./ -f ./build/paymaster.Dockerfile

start-dev:
	if docker ps -a -q -f name=paymaster-db | grep -q . ; then \
		docker stop paymaster-db; \
		docker rm paymaster-db; \
	fi
	docker run --name paymaster-db -p 5433:5432 -e POSTGRES_PASSWORD=123456 -e POSTGRES_DB=paymaster -d postgres
	until docker exec paymaster-db pg_isready -h localhost -p 5432 -U postgres > /dev/null; do \
		echo "Waiting for postgres to be ready..."; \
		sleep 1; \
	done
	echo "Postgres is ready."
	go build -o $(PWD)/build/bin/paymaster ./cmd/
	$(PWD)/build/bin/paymaster --db --db.migrate
	$(PWD)/build/bin/paymaster --config ./conf/local.json --log.debug --verbosity 4

stop-dev:
	if docker ps -q -f name=paymaster-db | grep -q . ; then \
		docker stop paymaster-db; \
		docker rm paymaster-db; \
	fi
	pkill -f paymaster || true
