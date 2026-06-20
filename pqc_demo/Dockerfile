# ── Build stage: compile liboqs C library + Python deps ─────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build liboqs (C library) from source
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON && \
    ninja -C liboqs/build install

# Install Python dependencies (liboqs-python wraps the compiled liboqs above)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage: slim image with just what's needed to run ────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Bring in compiled liboqs shared library + headers
COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/include/ /usr/local/include/
RUN ldconfig

# Bring in installed Python packages
COPY --from=builder /install /usr/local

WORKDIR /app
COPY . .

ENV PYTHONUNBUFFERED=1
ENV LD_LIBRARY_PATH=/usr/local/lib

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]