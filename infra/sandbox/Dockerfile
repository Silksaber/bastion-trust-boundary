# The scanner sandbox image.
#
# Everything a scan needs is baked in at build time, because at run time there is
# nothing to fetch from: the container gets no network namespace at all (ADR-004).
# That is the single fact that shapes this file. Semgrep's rules, Trivy's
# vulnerability database, OSV's offline database and Kubescape's control library are
# all downloaded here, once, and are read-only thereafter.
#
# The consequence is worth stating plainly rather than discovering later: **this image
# is only as current as the day it was built.** Refreshing threat data is an image
# rebuild, the build date is recorded in the image, and the worker stores the scanner
# versions on every run so a stale scan is visible rather than silent.
#
# Three other deliberate choices:
#
#   * **It ships interpreters and no package managers.** `python3` (with `pytest`) and
#     `node` are here because a validator proves a finding by *running* the vulnerable
#     code; `npm`, `npx` and any `pip install` at run time are not, because resolving a
#     dependency tree means executing install scripts out of a lockfile the attacker
#     wrote, inside the process whose whole job is handling that attacker's code. An
#     interpreter changes nothing about the boundary — the profile is the boundary. A
#     package manager changes the threat model. See ADR-050.
#   * **The base is `python:3.12-bookworm`, not `-slim`.** The full image already
#     carries git — which Gitleaks needs to read history and Checkov shells out to —
#     so the image needs no `apt` layer at all. That also keeps the build working
#     behind an HTTP proxy that intercepts Debian's plain-HTTP mirrors; the same
#     reasoning removed the API image's apt layer in Stage 1.
#   * **Nothing here runs as root at run time.** The image ships a `sandbox` user and
#     the runtime additionally forces `--user`, `--cap-drop ALL`, a read-only root
#     filesystem and a seccomp allow-list. See `infra/sandbox/README.md`.

FROM python:3.12-bookworm

# One line to bump. Every version is pinned: a scan that silently changed which
# analyser produced it is a scan whose diff nobody can explain.
ARG SEMGREP_VERSION=1.174.0
ARG CHECKOV_VERSION=3.3.13
ARG TRIVY_VERSION=0.74.0
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_SCANNER_VERSION=2.5.1
ARG KUBESCAPE_VERSION=4.0.12
# Stage 4: the runner a patch's verification uses, and the validator an IaC patch
# is checked with. Both pinned for the same reason the scanners are — a version bump
# is a change to what the image can prove, and it should be visible in the diff.
ARG PYTEST_VERSION=8.3.4
ARG TERRAFORM_VERSION=1.9.8
ARG SEMGREP_RULES_REF=develop
# Operation SAST Stage 11: the runtime the validator did not have. An LTS line,
# because it is the one that will still be receiving security fixes when this image is
# rebuilt in a year, and 24 is new enough to execute a `.ts` file with no toolchain —
# type stripping is native from 22.18, and shipping a transpiler and its dependency
# tree into a network-less sandbox was the alternative.
ARG NODE_VERSION=24.20.0
# System understanding (ADR-067): the parser the extractor uses to read TypeScript and
# JavaScript, and the three workflow/IaC/data-flow readers. Every one is pinned for the
# same reason the scanners are.
ARG TREE_SITTER_VERSION=0.23.2
ARG TREE_SITTER_TYPESCRIPT_VERSION=0.23.2
ARG TREE_SITTER_JAVASCRIPT_VERSION=0.23.1
ARG ZIZMOR_VERSION=1.32.0
ARG POUTINE_VERSION=1.1.6
ARG BEARER_VERSION=2.1.3

# Set by BuildKit. Every binary below is fetched per-architecture; the alternative is
# an image that works on the developer's laptop and not on the runner.
ARG TARGETARCH

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BASTION_SANDBOX=1

RUN mkdir -p /opt/bastion

# --- Python-based scanners --------------------------------------------------
RUN pip install --no-cache-dir \
        "semgrep==${SEMGREP_VERSION}" \
        "checkov==${CHECKOV_VERSION}"

# --- Go-based scanners ------------------------------------------------------
# Downloaded from their release pages rather than built, which is what every one of
# these projects publishes as the supported path.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH=Linux-64bit; GO_ARCH=amd64; GITLEAKS_ARCH=x64 ;; \
      arm64) TRIVY_ARCH=Linux-ARM64; GO_ARCH=arm64; GITLEAKS_ARCH=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz"; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    \
    curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    \
    curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${GO_ARCH}"; \
    \
    curl -fsSL -o /usr/local/bin/kubescape \
      "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_${GO_ARCH}"; \
    \
    chmod 0755 /usr/local/bin/trivy /usr/local/bin/gitleaks \
               /usr/local/bin/osv-scanner /usr/local/bin/kubescape; \
    rm -f /tmp/trivy.tgz /tmp/gitleaks.tgz

# --- Semgrep rules ----------------------------------------------------------
# `--config p/default` resolves against Semgrep's registry over the network, so the
# rules are cloned here instead. Only the security rulesets are kept: the full
# repository includes correctness and best-practice rules that would turn a security
# scan into a linter and bury the findings that matter.
RUN set -eux; \
    git clone --depth 1 --branch "${SEMGREP_RULES_REF}" \
        https://github.com/semgrep/semgrep-rules.git /tmp/semgrep-rules; \
    mkdir -p /opt/bastion/semgrep-rules; \
    cd /tmp/semgrep-rules; \
    find . -path '*/security/*' -name '*.yaml' ! -name '*.test.yaml' \
        -exec cp --parents {} /opt/bastion/semgrep-rules/ \; ; \
    rm -rf /tmp/semgrep-rules; \
    echo "rules: $(find /opt/bastion/semgrep-rules -name '*.yaml' | wc -l)"

# --- Offline threat data ----------------------------------------------------
RUN set -eux; \
    TRIVY_CACHE=/tmp/trivy-cache; \
    trivy --cache-dir "${TRIVY_CACHE}" image --download-db-only; \
    mkdir -p /opt/bastion/trivy-db; \
    cp "${TRIVY_CACHE}/db/trivy.db" "${TRIVY_CACHE}/db/metadata.json" /opt/bastion/trivy-db/; \
    rm -rf "${TRIVY_CACHE}"

RUN set -eux; \
    mkdir -p /opt/bastion/kubescape-artifacts; \
    kubescape download artifacts --output /opt/bastion/kubescape-artifacts

# OSV-Scanner downloads a per-ecosystem database, and it only downloads the ecosystems
# it can see in front of it. The seed directory below exists purely to name them: one
# manifest per ecosystem we support, containing one package each. Without it the image
# would ship a database covering whatever happened to be in the last thing built.
RUN set -eux; \
    mkdir -p /tmp/osv-seed; \
    cd /tmp/osv-seed; \
    printf 'flask==0.12.2\n' > requirements.txt; \
    printf '{"name":"seed","lockfileVersion":2,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}\n' > package-lock.json; \
    printf 'module seed\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n' > go.mod; \
    printf 'GEM\n  specs:\n    rack (2.0.6)\n\nDEPENDENCIES\n  rack\n' > Gemfile.lock; \
    printf '[[package]]\nname = "time"\nversion = "0.1.44"\n' > Cargo.lock; \
    printf '{"packages":[{"name":"guzzlehttp/guzzle","version":"6.5.0"}]}\n' > composer.lock; \
    printf '<project><modelVersion>4.0.0</modelVersion><groupId>seed</groupId><artifactId>seed</artifactId><version>1</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>\n' > pom.xml; \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/bastion/osv-db \
      osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
      --format json -r /tmp/osv-seed > /dev/null 2>&1 || true; \
    rm -rf /tmp/osv-seed; \
    test -d /opt/bastion/osv-db/osv-scalibr; \
    du -sh /opt/bastion/osv-db

# The two Stage 4 additions sit here, after the threat-data downloads, so adding
# them reuses every expensive cached layer above instead of invalidating it. A
# rebuild for a pytest bump should cost seconds, not fifteen minutes.
# --- Terraform: NOT installed, and deliberately so --------------------------
# Stage 4's Definition of Done asks that an IaC remediation be accepted by
# `terraform validate`. That needs the real binary, and the layer to fetch it was
# written, reviewed, and then removed — because `releases.hashicorp.com` answers 404
# for every path from the network this was built on, including its own index. A build
# step that is known to fail in the only environment it can be tested in is worse than
# an honest gap.
#
# Adding it back is one layer and one pinned version, in this spot, from a network
# that can reach HashiCorp. Until then the IaC checkpoint is recorded as not
# demonstrated rather than quietly counted as done. `terraform validate` is offline —
# it needs no credentials and no network at run time — so nothing about the sandbox
# boundary stands in the way.

# --- Verification tooling (Stage 4) -----------------------------------------
# Stage 4 verifies a patch by running the repository's own test suite in here, and
# Stage 3's image had nothing to run one with — the first live attempt failed with
# "No module named pytest".
#
# What this can and cannot do is worth being clear about, because it bounds a claim
# the product makes to customers. There is no network in this sandbox, so a
# repository's *dependencies* cannot be installed at verification time. A suite that
# needs Flask, or a private package, will not run here. `pytest` is baked in because
# it is the runner itself rather than a dependency, and a suite that needs nothing
# beyond the standard library — which the fixture's is — verifies properly.
#
# The honest consequence: `tests_passed` is three-valued for a reason, and a
# repository whose suite cannot run offline gets `None` and a pull request that says
# so in words. It never gets a `true` it did not earn.
RUN pip install --no-cache-dir "pytest==${PYTEST_VERSION}"

# --- A JavaScript runtime (Operation SAST, Stage 11) ------------------------
# The dress rehearsal put a number on the gap this closes: on a real TypeScript
# repository, 0 of 12 findings were confirmed, and the validator's own stored evidence
# said why — `could not start: [Errno 2] No such file or directory: node`. The corpus
# said the same thing more precisely: JavaScript was the only language at 0% confirmed
# and Python, the only language with a runtime in here, was the best at 58%. Same
# scanners, same prompts, same rubric.
#
# **Only `bin/node`.** The official tarball also carries `npm` and `npx`, and they are
# deliberately dropped on the floor rather than installed. A package manager inside the
# process whose whole job is handling attacker-controlled code is strictly worse than
# every finding it would confirm: `npm install` executes install scripts out of a
# lockfile the attacker wrote. There is no network in here to install from, but "there
# is nothing to run it with" is a better boundary than "it would fail if it ran", and
# the last line of this layer is what keeps it true.
#
# **This does not weaken the sandbox**, and the argument is worth writing down because
# somebody will ask. The image already ships a full CPython, so arbitrary code
# execution inside the container was always possible and always contained. What
# contains it is `--network none`, the read-only root, `noexec` on both tmpfs mounts,
# `--cap-drop ALL`, `no-new-privileges`, the seccomp allow-list and the caps — none of
# which this layer touches. An interpreter is not the boundary; the profile is.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) NODE_ARCH=x64 ;; \
      arm64) NODE_ARCH=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    NODE_DIR="node-v${NODE_VERSION}-linux-${NODE_ARCH}"; \
    curl -fsSL -o /tmp/node.tar.xz \
      "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_DIR}.tar.xz"; \
    tar -xJf /tmp/node.tar.xz -C /tmp "${NODE_DIR}/bin/node"; \
    install -m 0755 "/tmp/${NODE_DIR}/bin/node" /usr/local/bin/node; \
    rm -rf /tmp/node.tar.xz "/tmp/${NODE_DIR}"; \
    node --version; \
    printf 'type Discount = { off: number };\nconst d: Discount = { off: 10 };\nif (d.off !== 10) process.exit(1);\n' > /tmp/probe.ts; \
    node /tmp/probe.ts; \
    rm -f /tmp/probe.ts; \
    ! command -v npm; \
    ! command -v npx

# --- System understanding (ADR-067) -----------------------------------------
# The extractor reads structure with the standard library and, for TypeScript and
# JavaScript, tree-sitter. The three tools below read what a parser cannot: zizmor for
# GitHub Actions, poutine for CI/CD pipeline misconfiguration, bearer for data flows.
# Each writes JSON into the run's out directory; a tool that fails is recorded as a gap
# and is not fatal, so a broken release never takes the whole feature down.
#
# This layer sits after the expensive threat-data downloads on purpose: adding a
# tree-sitter bump should reuse every cached layer above it.
RUN pip install --no-cache-dir \
        "tree-sitter==${TREE_SITTER_VERSION}" \
        "tree-sitter-typescript==${TREE_SITTER_TYPESCRIPT_VERSION}" \
        "tree-sitter-javascript==${TREE_SITTER_JAVASCRIPT_VERSION}" \
        "zizmor==${ZIZMOR_VERSION}"

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) POUTINE_ARCH=x86_64; BEARER_ARCH=amd64 ;; \
      arm64) POUTINE_ARCH=arm64; BEARER_ARCH=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    curl -fsSL -o /tmp/poutine.tgz \
      "https://github.com/boostsecurityio/poutine/releases/download/v${POUTINE_VERSION}/poutine_Linux_${POUTINE_ARCH}.tar.gz"; \
    tar -xzf /tmp/poutine.tgz -C /usr/local/bin poutine; \
    \
    curl -fsSL -o /tmp/bearer.tgz \
      "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_${BEARER_ARCH}.tar.gz"; \
    tar -xzf /tmp/bearer.tgz -C /usr/local/bin bearer; \
    \
    chmod 0755 /usr/local/bin/poutine /usr/local/bin/bearer; \
    rm -f /tmp/poutine.tgz /tmp/bearer.tgz

# --- Our own Semgrep rules --------------------------------------------------
# Operation SAST Stage 3. The vendored OSS ruleset is framework-shaped: its path
# traversal, SSRF, template injection and command injection rules taint from a flask,
# django, express or aws-lambda request object, so a plain helper that takes the value
# as an argument matches none of them. That is most of an SME's code, and it measured
# as 20 of the corpus's 22 misses.
#
# These land *inside* the vendored tree, one `bastion/` directory per language, for two
# reasons. Semgrep names a rule after the path it loaded it from, so the ids read
# `python.bastion.path-traversal.path-traversal-read` and say plainly in the UI that
# the rule is ours rather than upstream's. And `_configs()` in the adapter narrows by
# language directory, so a rule placed here is picked up by that narrowing for free.
#
# Every rule carries a `corpus-cases` key in its metadata naming the planted cases that
# justify it. A rule with no corpus case behind it does not belong here — see
# `fixtures/sast-corpus/MANIFEST.toml` and `make sast-scorecard`.
COPY rules/ /opt/bastion/semgrep-rules/

# The structure extractor. It runs against a checkout inside the sandbox and never
# imports or executes customer code — it parses. `understand/extract.py` is invoked as
# `python3 /opt/bastion/understand/extract.py <repo_dir> <out_dir>`.
COPY understand/ /opt/bastion/understand/

# --- The entrypoint ---------------------------------------------------------
COPY entrypoint.py /opt/bastion/entrypoint.py

RUN set -eux; \
    date -u +%Y-%m-%dT%H:%M:%SZ > /opt/bastion/BUILD_DATE; \
    chmod 0755 /opt/bastion/entrypoint.py; \
    chmod -R a+rX /opt/bastion; \
    useradd --uid 65532 --create-home --home-dir /home/sandbox --shell /usr/sbin/nologin sandbox

# The runtime overrides this with an explicit `--user`; declaring it here means the
# image is not root-by-default even if somebody runs it by hand.
USER 65532:65532

ENTRYPOINT ["python3", "/opt/bastion/entrypoint.py"]
