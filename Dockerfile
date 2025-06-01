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
ENV MVPS_VERSION=v0.1.5
ENV COSIGN_VERSION=v2.2.3

# Download and install cosign
RUN curl -fsSL https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64 -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Download MVPS binaries and cosign bundles
RUN curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-te -o /build/mvps-te && \
    curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-te.cosign-bundle -o /build/mvps-te.cosign-bundle && \
    curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-s3-gc -o /build/mvps-s3-gc && \
    curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-s3-gc.cosign-bundle -o /build/mvps-s3-gc.cosign-bundle

# Verify binaries with cosign bundles
RUN cosign verify-blob --bundle /build/mvps-te.cosign-bundle \
    --certificate-identity-regexp="^https://github\\.com/losfair/mvps/\\.github/workflows/ci\\.yml@refs/tags/" \
    --certificate-oidc-issuer-regexp="^https://token\\.actions\\.githubusercontent\\.com$" \
    /build/mvps-te && \
    cosign verify-blob --bundle /build/mvps-s3-gc.cosign-bundle \
    --certificate-identity-regexp="^https://github\\.com/losfair/mvps/\\.github/workflows/ci\\.yml@refs/tags/" \
    --certificate-oidc-issuer-regexp="^https://token\\.actions\\.githubusercontent\\.com$" \
    /build/mvps-s3-gc && \
    chmod +x /build/mvps-te /build/mvps-s3-gc

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies (nbd-client required by the provisioner)
RUN apt-get update && apt-get install -y \
    nbd-client e2fsprogs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the provisioner binary
COPY --from=builder /build/mvps-provisioner /app/mvps-provisioner

# Copy mvps-te and mvps-s3-gc binary
COPY --from=mvps-builder /build/mvps-te /usr/bin/mvps-te
COPY --from=mvps-builder /build/mvps-s3-gc /usr/bin/mvps-s3-gc

# Set default environment variable for socket path
ENV PROVISIONER_LISTEN_PATH=/var/run/mvps-provisioner.sock

# Run the provisioner
ENTRYPOINT ["/app/mvps-provisioner"]
