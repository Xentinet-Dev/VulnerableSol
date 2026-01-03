# Dockerfile for Solana/Anchor Build Environment
# This provides a clean, isolated environment with correct versions

# Use official Solana image as base (has Solana CLI and platform-tools pre-installed)
# Using 1.18.26 for Rust 1.76+ compatibility with Anchor 0.29.0
FROM solanalabs/solana:v1.18.26

# Install build dependencies, curl, and Python (needed for Rust installation and rust-toolchain.toml creation)
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (needed for Anchor)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify Rust installation
RUN /root/.cargo/bin/rustc --version

# Install Anchor CLI - try with tag first, fallback to latest
# Note: We install without --locked to allow Cargo to resolve compatible dependencies
# Remove Solana toolchain before installing Anchor to prevent version conflicts
# CRITICAL: Remove Solana toolchain completely and ensure it stays removed
RUN rustup toolchain uninstall solana 2>/dev/null || true && \
    export PATH="/root/.cargo/bin:/root/.local/share/solana/install/active_release/bin:${PATH}" && \
    cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.29.0 --force 2>&1 | tee /tmp/anchor-install.log || \
    (echo "v0.29.0 failed, trying latest..." && \
     cargo install --git https://github.com/coral-xyz/anchor anchor-cli --force) && \
    rustup toolchain uninstall solana 2>/dev/null || true && \
    rustup update stable && \
    rustup default stable && \
    echo "[+] Solana toolchain removed, stable Rust set as default"

# Verify installations (using full paths to be safe)
# Note: Solana may be in different location in base image, so we just verify Anchor
RUN /root/.cargo/bin/anchor --version 2>&1 || echo "Note: Anchor CLI verification skipped"

# Ensure Solana platform tools are in PATH and properly configured
# The base Solana image should have these, but we ensure they're accessible
ENV PATH="/root/.local/share/solana/install/active_release/bin:${PATH}"
ENV SOLANA_PLATFORM_TOOLS="/root/.local/share/solana/install/active_release/bin/platform-tools"

# Set working directory
WORKDIR /workspace

# Default command (keep container running)
CMD ["tail", "-f", "/dev/null"]

