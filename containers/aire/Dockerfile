FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    R2PM_PFX=/root/.config/radare2/prefix \
    PATH="/root/.local/bin:/root/.config/radare2/prefix/bin:${PATH}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        file \
        build-essential \
        pkg-config \
        libc6-i386 \
        lib32stdc++6 \
        lib32gcc-s1 \
        gdb \
        gdbserver && \
    git clone --depth 1 https://github.com/radareorg/radare2.git /opt/radare2 && \
    cd /opt/radare2 && sys/install.sh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy source for local installs (expects build context at repo root)
WORKDIR /opt/aire
COPY . /opt/aire

RUN pip install --no-cache-dir /opt/aire/double_agent /opt/aire/aire_core pytest requests

# Build a known x86_64 test binary for aire_core tests
RUN mkdir -p /opt/aire/tests && \
    cat > /opt/aire/tests/gdb_test_bin.c <<'EOF' && \
    gcc -static -s -o /opt/aire/tests/gdb_test_bin /opt/aire/tests/gdb_test_bin.c && \
    chmod +x /opt/aire/tests/gdb_test_bin
#include <stdio.h>
#include <stdint.h>

static int square(int x) { return x * x; }

int main(int argc, char **argv) {
    (void)argv;
    printf("gdb_test_secret=%d\n", square(argc));
    return square(argc) & 0xff;
}
EOF

CMD ["/bin/sh", "-c", "tail -f /dev/null"]
