.PHONY: compile test

compile:
	go build -v ./...

test:
	go test -race -v ./...