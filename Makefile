.PHONY: check test
COVERAGE_FILE ?= coverage.txt

check:
	go vet ./...
	golangci-lint run

test:
	go test -v -race -coverprofile=${COVERAGE_FILE} -covermode=atomic ./...
