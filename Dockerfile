FROM rust:1.87 AS builder

WORKDIR /usr/src/hash-sig-cli

# Copy manifest and pre-fetch dependencies (cached if unchanged)
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch
RUN rm -rf src

# Copy actual sources and build the binary
COPY src ./src
RUN cargo build --release --bin hashsig

# Use a smaller base image for the final image
FROM debian:bookworm-slim

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/hash-sig-cli/target/release/hashsig /usr/local/bin/hashsig

# Set the entry point for the container
ENTRYPOINT ["hashsig"]
