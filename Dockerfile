# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/rylanq/ryprox/internal/version.Version=${VERSION} -X github.com/rylanq/ryprox/internal/version.Commit=${COMMIT}" \
    -o /out/ryprox ./cmd/ryprox \
 && mkdir -p /out/data

# ---- run ----
# Distroless: no shell, no package manager, runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ryprox /usr/local/bin/ryprox
# The data folder must belong to the non-root user, or RyProx can't write to it.
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV RYPROX_DATA=/data \
    RYPROX_HTTP=:80 \
    RYPROX_HTTPS=:443 \
    RYPROX_ADMIN=0.0.0.0:8081
VOLUME /data
EXPOSE 80 443 8081
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/ryprox", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/ryprox"]
CMD ["serve"]
