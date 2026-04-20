FROM golang:1.24 AS builder

WORKDIR /app

# clone k8sgpt source directly
RUN apt-get update && apt-get install -y git \
 && git clone https://github.com/k8sgpt-ai/k8sgpt.git .

RUN go mod tidy
RUN go build -o k8sgpt main.go

FROM ubuntu:22.04

WORKDIR /root/
COPY --from=builder /app/k8sgpt .

RUN apt-get update && apt-get install -y ca-certificates

ENTRYPOINT ["./k8sgpt"]