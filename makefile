.PHONY:	test
test:
	go vet ./...
	go test ./...

.PHONY:	bin
bin:
	mkdir -p bin
	go build -v -o bin ./cmd/authz_mw_cli
mock:
	mockery --all --with-expecter=true --inpackage=true
