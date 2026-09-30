FROM golang:1.24-bookworm AS build
WORKDIR /src/agent
COPY agent/go.mod ./
RUN go mod download
COPY agent/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(cat VERSION)" -o /vm-agent-linux-amd64 ./cmd/vm-agent

FROM alpine:3.22
COPY --from=build /vm-agent-linux-amd64 /bundle/vm-agent-linux-amd64
COPY --from=build /src/agent/VERSION /bundle/VERSION
COPY deploy/agent/install.sh /bundle/install.sh
CMD ["sh", "-ec", "cp /bundle/vm-agent-linux-amd64 /dist/vm-agent-linux-amd64; cp /bundle/install.sh /dist/install.sh; cp /bundle/VERSION /dist/VERSION; cd /dist; sha256sum vm-agent-linux-amd64 install.sh > SHA256SUMS; chmod 644 vm-agent-linux-amd64 install.sh VERSION SHA256SUMS"]
