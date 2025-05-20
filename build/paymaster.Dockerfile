# Download Go dependencies
FROM scrolltech/go-alpine-builder:1.20 as builder

ADD . /paymaster
ENV GOPROXY="https://goproxy.cn,direct"
RUN cd /paymaster && \
    go mod tidy &&  \
    go build -v -o ./build/bin/paymaster ./cmd

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest
COPY --from=builder /paymaster/build/bin/paymaster /bin/
WORKDIR /app
ENTRYPOINT ["paymaster"]
