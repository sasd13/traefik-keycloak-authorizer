export GO111MODULE=on

.PHONY: default
default: lint test

.PHONY: build
build:
	go build ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: format
format:
	go fmt ./...

.PHONY: test
test:
	go test -v -cover ./...

.PHONY: yaegi_test
yaegi_test:
	yaegi test -v .

.PHONY: vendor
vendor:
	go mod vendor

.PHONY: clean
clean:
	rm -rf ./vendor