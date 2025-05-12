# Build stage for mvps-provisioner
FROM golang:1.23-bookworm AS builder

WORKDIR /build

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the provisioner
RUN CGO_ENABLED=0 go build -o mvps-provisioner

# MVPS-TE download and verification stage
FROM debian:bookworm-slim AS mvps-builder

# Install curl for downloading binaries
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Set MVPS version and cosign version
ENV MVPS_VERSION=v0.1.2
ENV COSIGN_VERSION=v2.2.3

# Download and install cosign
RUN curl -fsSL https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64 -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Download MVPS binaries and cosign bundles
RUN curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-te -o /build/mvps-te && \
    curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-te.cosign-bundle -o /build/mvps-te.cosign-bundle

# Verify binaries with cosign bundles
RUN cosign verify-blob --bundle /build/mvps-te.cosign-bundle \
    --certificate-identity-regexp="^https://github\\.com/losfair/mvps/\\.github/workflows/ci\\.yml@refs/tags/" \
    --certificate-oidc-issuer-regexp="^https://token\\.actions\\.githubusercontent\\.com$" \
    /build/mvps-te && \
    chmod +x /build/mvps-te

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies (nbd-client required by the provisioner)
RUN apt-get update && apt-get install -y \
    nbd-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the provisioner binary
COPY --from=builder /build/mvps-provisioner /app/mvps-provisioner

# Copy mvps-te binary
COPY --from=mvps-builder /build/mvps-te /usr/bin/mvps-te

# Copy image configuration
COPY images.json /app/images.json

# Set default environment variable for socket path
ENV PROVISIONER_LISTEN_PATH=/var/run/mvps-provisioner.sock

# Run the provisioner
ENTRYPOINT ["/app/mvps-provisioner"]