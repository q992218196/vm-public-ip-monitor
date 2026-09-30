FROM golang:1.24-bookworm AS build
WORKDIR /src/agent
COPY agent/go.mod ./
RUN go mod download
COPY agent/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /vm-agent-linux-amd64 ./cmd/vm-agent

FROM alpine:3.22
COPY --from=build /vm-agent-linux-amd64 /bundle/vm-agent-linux-amd64
COPY deploy/agent/install.sh /bundle/install.sh
CMD ["sh", "-ec", "cp /bundle/vm-agent-linux-amd64 /dist/vm-agent-linux-amd64; cp /bundle/install.sh /dist/install.sh; cd /dist; sha256sum vm-agent-linux-amd64 install.sh > SHA256SUMS; chmod 644 vm-agent-linux-amd64 install.sh SHA256SUMS"]
