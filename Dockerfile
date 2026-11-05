FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dns-probe ./cmd/probe

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/dns-probe /app/dns-probe
COPY configs /app/configs
USER nonroot:nonroot
ENTRYPOINT ["/app/dns-probe", "-config", "/app/configs/targets.yaml"]
