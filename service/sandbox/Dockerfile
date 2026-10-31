# ARBITER sandbox: forge / anvil / cast / solc / Slither for ONE job, no network, no keys.
#
# Built by service/sandbox/build.sh, which copies THIS machine's verified binaries into the
# build context (sha256 checked twice: by build.sh against tools.lock, and here), so the
# container runs exactly the toolchain the harness was measured with -- nothing is
# downloaded for forge or solc. The network is used at build time only, for apt, PyPI
# (slither-analyzer, pinned) and the Solidity dependency cache (build_dep_cache.sh).
#
# Runtime (arbiter/arbiter/sandbox.py): --network none, --read-only, non-root, tmpfs /tmp,
# memory / cpu / pids limits, only the job directory mounted, environment = PATH only.
FROM ubuntu:24.04

ARG UID=1000
ARG GID=1000

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git python3 python3-venv libudev1 procps \
 && rm -rf /var/lib/apt/lists/*

# Slither, pinned to the version of runs/slither.json; in a venv, not the system Python.
RUN python3 -m venv /opt/slither \
 && /opt/slither/bin/pip install --no-cache-dir slither-analyzer==0.11.6 \
 && /opt/slither/bin/slither --version

# The toolchain from this machine, checked against tools.lock (same file build.sh wrote).
COPY tools.lock /opt/arbiter/tools.lock
COPY bin/forge bin/anvil bin/cast /usr/local/bin/
COPY svm/ /opt/svm/
RUN cd / && sha256sum -c /opt/arbiter/tools.lock

# Solidity dependency cache (OpenZeppelin, forge-std, solmate, uniswap, chainlink).
COPY build_dep_cache.sh /opt/arbiter/build_dep_cache.sh
RUN bash /opt/arbiter/build_dep_cache.sh /opt/soldeps \
 && find /opt/soldeps -name .git -type d -prune -exec rm -rf {} + \
 && chmod -R a+rX /opt/soldeps

# The job user. Same uid/gid as the host user, so files forge writes in the mounted job
# directory belong to whoever started the job. forge finds solc through ~/.svm.
RUN (userdel -r ubuntu 2>/dev/null || true) \
 && groupadd -g ${GID} arbiter && useradd -m -u ${UID} -g ${GID} -s /bin/bash arbiter \
 && ln -s /opt/svm /home/arbiter/.svm

ENV PATH=/usr/local/bin:/opt/slither/bin:/usr/bin:/bin
USER arbiter
WORKDIR /home/arbiter
CMD ["sleep", "infinity"]
