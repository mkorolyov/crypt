.PHONY: gen

compile:
	go build -v ./...

test:
	go test -race -v ./...