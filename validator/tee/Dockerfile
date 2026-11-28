ARG RUST_BASE=rust:1.94.1-slim-bookworm@sha256:f845b308e3104231c98dba2dab952ebd54e35cd6ab8ef4a230ecb38e2315f20c
ARG PYTHON_BASE=python:3.12.10-slim-bookworm@sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4
FROM ${RUST_BASE} AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/main.rs src/main.rs
RUN --network=none cargo build --locked --offline --release --no-default-features

COPY --from=assets foundry.tar.gz age.tar.gz solc /build/assets/
COPY tee/build-assets.sha256 /build/assets/
RUN --network=none (cd assets && sha256sum -c build-assets.sha256) \
    && mkdir /tools \
    && tar -xzf assets/foundry.tar.gz -C /tools forge anvil \
    && tar -xzf assets/age.tar.gz -C /tools --strip-components=1 age/age \
    && install -m 0755 assets/solc /tools/solc \
    && install -m 0755 target/release/validator /tools/validator

FROM ${PYTHON_BASE} AS common
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 RAYON_NUM_THREADS=1
WORKDIR /app
COPY --from=build /tools/ /usr/local/bin/
COPY tee/protocol.py tee/guest.py tee/workload.py tee/experiment.json ./
COPY tee/fixture/ ./fixture/
ENTRYPOINT ["python3", "/app/guest.py"]

FROM common AS local
COPY tee/mock_quote.py ./
CMD ["serve", "--mode", "mock"]

FROM common AS tdx
CMD ["serve", "--mode", "tdx"]
