# Download Go dependencies
FROM golang:1.23-alpine as builder

ADD . /paymaster
ENV GOPROXY="https://goproxy.cn,direct"
RUN cd /paymaster && \
    CGO_ENABLED=0 GOOS=linux go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -v -o ./build/bin/paymaster ./cmd

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest
COPY --from=builder /paymaster/build/bin/paymaster /bin/
WORKDIR /app
ENTRYPOINT ["paymaster"]
