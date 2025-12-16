# --- STAGE 1: Build the Rust binary and Python extension ---
FROM rust:latest AS builder
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    bubblewrap \
    musl-tools \
    python3 python3-pip python3-dev python3-venv \
    git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all code
COPY . .

# Create and configure the python virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYO3_PYTHON=/opt/venv/bin/python

# Build the python wheel
RUN pip install maturin
RUN cd bindings/python && maturin build --release -o ../../dist

# Build the bubbleproc CLI executable
RUN cargo build --release --bin bubbleproc

# --- STAGE 2: Minimal Runtime Environment ---
FROM debian:sid AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    bubblewrap \
    curl \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install the python wheel
COPY --from=builder /app/dist/*.whl .
RUN pip install *.whl --break-system-packages

# Copy the built binary
COPY --from=builder /app/target/release/bubbleproc /usr/local/bin/bubbleproc

# Set up a fake user environment for testing isolation
RUN useradd -m bubbleuser
USER bubbleuser
WORKDIR /home/bubbleuser

# Create a fake "secret" that should be blocked
RUN mkdir -p /home/bubbleuser/.ssh
RUN echo "SECRET_KEY_123" > /home/bubbleuser/.ssh/id_rsa

# Copy test files with executable permissions
COPY --chmod=+x test_security.sh test_security.sh
COPY --chmod=+x test_python_api.py test_python_api.py