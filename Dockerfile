# Multi-stage: compila el release en la imagen de Rust y corre en distroless/cc.
# El host NO necesita Rust: todo se compila dentro del contenedor.
FROM rust:1-bookworm AS build
# cmake/clang: los necesita el proveedor cripto de async-nats (aws-lc-rs) al compilar.
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /
COPY --from=build /src/target/release/onix-guard /onix-guard
EXPOSE 8083
USER nonroot:nonroot
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/onix-guard", "--healthcheck"]
ENTRYPOINT ["/onix-guard"]
