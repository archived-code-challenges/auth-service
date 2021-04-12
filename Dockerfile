################
FROM golang:1.15 as builder
RUN go version
WORKDIR /go/src/github.com/noelruault/golang-authentication/

# The first dot refers to the local path itself, the second one points the WORKDIR path
COPY . .
RUN [ -d bin ] || mkdir bin
RUN GOOS=linux CGO_ENABLED=0 go build -o bin/ ./cmd/...

################
FROM alpine

COPY --from=builder /go/src/github.com/noelruault/golang-authentication/bin/ bin

RUN chmod +x /bin/api

ENTRYPOINT ENV=$ENV ./bin/api $ENV_ARGS
