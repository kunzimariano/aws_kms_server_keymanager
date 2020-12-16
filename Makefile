
build:
	env GOOS=linux go build -o kms cmd/main.go
test:
	go test ./... -v