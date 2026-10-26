# jankhunt42 detonate runner: node + python + strace, unprivileged. Built once by the operator; never from a repository.
FROM docker.io/library/node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace python3 python3-pip python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 runner
USER 10001
WORKDIR /work
