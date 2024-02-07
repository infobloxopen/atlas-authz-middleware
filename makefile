.PHONY:	test
test:
	go mod vendor
	go vet ./...
	go test ./...

.PHONY:	bin
bin:
	mkdir -p bin
	go build -v -o bin ./cmd/authz_mw_cli
