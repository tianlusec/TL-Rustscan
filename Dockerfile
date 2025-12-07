FROM rust:latest AS builder

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/TL-Rustscan /usr/local/bin/TL-Rustscan

ENTRYPOINT ["TL-Rustscan"]

CMD ["--help"]
