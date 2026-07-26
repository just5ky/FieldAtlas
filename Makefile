.PHONY: generate test serve

generate:
	go run ./cmd/build

test:
	go vet ./...
	go test ./...

serve:
	cd docs && python3 -m http.server 8000
