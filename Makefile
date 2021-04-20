SOURCES = $(shell find . -type f -iname "*.go")

.PHONY: all build vet fmt test run image clean private

all: test

vet:
	go vet ./...

fmt: private
	go fmt ./...

test: fmt vet
	go test ./... -coverprofile cover.out

clean:
	rm -rf bin/
