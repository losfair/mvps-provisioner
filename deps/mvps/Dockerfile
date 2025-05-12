# Build stage
FROM debian:bookworm-slim AS builder

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
    curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-s3-gc -o /build/mvps-s3-gc && \
    curl -fsSL https://github.com/losfair/mvps/releases/download/${MVPS_VERSION}/mvps-te.cosign-bundle -o /build/mvps-te.cosign-bundle && \
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

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only needed binaries from builder stage
COPY --from=builder /build/mvps-te /app/mvps-te
COPY --from=builder /build/mvps-s3-gc /app/mvps-s3-gc

ENTRYPOINT ["/app/mvps-te"]