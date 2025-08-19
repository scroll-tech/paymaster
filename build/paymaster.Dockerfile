# Download Go dependencies
FROM golang:1.23-alpine as builder

ADD . /paymaster
ENV GOPROXY="https://goproxy.cn,direct"
RUN cd /paymaster && \
    CGO_ENABLED=0 GOOS=linux go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -v -o ./build/bin/paymaster ./cmd

# Deploy stage with SSL certificate support
FROM alpine:latest

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

COPY --from=builder /paymaster/build/bin/paymaster /bin/
WORKDIR /app
ENTRYPOINT ["paymaster"]
