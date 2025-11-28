# Build Stage
FROM rust:latest AS builder

WORKDIR /usr/src/app
COPY . .

# Build the application in release mode
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

# Install necessary runtime dependencies (e.g., OpenSSL)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/TL-Rustscan /usr/local/bin/TL-Rustscan

# Set the entrypoint
ENTRYPOINT ["TL-Rustscan"]

# Default command (can be overridden)
CMD ["--help"]
