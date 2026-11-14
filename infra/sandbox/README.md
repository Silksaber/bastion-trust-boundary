# The sandbox

This directory is the trust boundary. Everything else in Stage 3 is plumbing.

The brief commits the product to running customers' code on our infrastructure —
*"all scanning compute runs on our own infrastructure, never on the client's
machine"* — which makes this the single most safety-critical component in the system.
Its isolation is proved by an adversarial test, not by a configuration review
([ADR-009](../../docs/DECISIONS.md#adr-009--sandbox-isolation-is-proved-adversarially-in-ci-from-stage-3)).

```
infra/sandbox/
├── Dockerfile           the scanner image: six analysers and all of their threat data
├── minimal.Dockerfile   the same entrypoint without the analysers, for the isolation test
├── entrypoint.py        the only process the sandbox starts
└── seccomp.json         the syscall allow-list, as a reviewable document
```

The flags themselves live in one place and one place only:
[`apps/worker/src/bastion_worker/sandbox/profile.py`](../../apps/worker/src/bastion_worker/sandbox/profile.py).
A second call site with a slightly different flag list is how a boundary quietly stops
being one, so there is exactly one function that builds a `docker run` command, and a
test asserts on its output without starting anything.

---

## The two channels

The container has no network namespace, no mount of any kind, and a read-only root
filesystem. That leaves exactly two ways in or out:

```
                     ┌──────────────────────────────────────┐
   tar on stdin ────►│  entrypoint.py                       │
   · plan.json       │   · extract to the /work tmpfs       │
   · repo/           │   · run each step, capped            │──► tar on stdout
                     │   · delete the checkout              │    · <step>.stdout
                     │   · tar /work/out                    │    · <step>.stderr
                     └──────────────────────────────────────┘    · reports, steps.json
```

**The entrypoint does not know what a scanner is.** It receives a list of commands and
returns what they printed. That is what makes Stage 3's promise — *adding an adapter
requires no changes outside `packages/scanners/`* — true rather than aspirational.

---

## What holds it shut

| Control | What it stops | Why not the obvious alternative |
|---|---|---|
| `--network none` | Every form of egress: DNS, TCP, cloud metadata | A firewall rule is a rule to get wrong. There is no interface here to misconfigure ([ADR-004](../../docs/DECISIONS.md#adr-004--rootless-containers-with-no-network-namespace-for-sandboxing)) |
| `--read-only` + tmpfs | Anything surviving the job, or being left for the next one | A writable layer is a place to plant something |
| `noexec` on `/work` | Executing a file out of the checkout | A repository is data, not a program. This makes that a kernel guarantee rather than a hope |
| `--cap-drop ALL`, `no-new-privileges` | Privilege escalation, including via a setuid binary in the image | A packaging mistake in a scanner image stops being an escape |
| `--user 65532` | Root, even inside the namespace | Combined with the read-only rootfs there is nothing a uid-0 process could reach |
| `seccomp.json` | `mount`, `unshare`, `setns`, `pivot_root`, `ptrace`, `bpf`, `keyctl`, the module loaders — and `clone` with any `CLONE_NEW*` flag | An allow-list defaulting to `EPERM`, so a syscall nobody thought about is denied rather than permitted |
| `--pids-limit`, `--memory`, `--cpus`, wall clock | A fork bomb, a memory hog, an infinite loop | All three are caps on our own infrastructure, not politeness |

And two absences that are deliberate:

- **No bind mount, not even `--init`.** `--init` would bind-mount an init binary from
  the host. The checkout arrives over stdin precisely so that "no host mount" can be
  literally true rather than nearly true.
- **No credential.** The installation token is used by the *worker* to clone and never
  crosses the boundary. `docker_run_argv` takes no secret to pass on, and a test
  searches the plan and the packed workspace for one.

---

## Offline by construction

There is no network in here, so nothing can be fetched at run time. Every scanner's
threat data is therefore baked into the image at build time:

| Scanner | What is baked in |
|---|---|
| Semgrep | the security rulesets from `semgrep-rules`, referenced by path rather than pulled from the registry |
| Trivy | the vulnerability database, symlinked into a writable cache at run time |
| OSV-Scanner | the per-ecosystem offline databases |
| Kubescape | the framework and control definitions |
| Gitleaks, Checkov | their rules ship inside the tools |

**The consequence is worth stating rather than discovering.** An image is only as
current as the day it was built. Refreshing threat data is an image rebuild; the build
date is recorded at `/opt/bastion/BUILD_DATE`, and the worker stores each tool's
version on every `scanner_runs` row, so a stale scan is visible rather than silent.

---

## Rootless

The profile makes the sandboxed *process* non-root. Whether the container **runtime
itself** runs rootless is a property of the deployment, and no amount of code in here
can assert it — so the worker asks, logs the answer on every start, and will refuse to
run at all when `SANDBOX_REQUIRE_ROOTLESS=true`.

That flag is off by default because Docker Desktop is not rootless and local
development is where this stage gets exercised. **On is the production posture.**

---

## Running it

```bash
make sandbox-image          # build the scanners (~4 GB, ~15 min, needs network)
make sandbox-test           # the adversarial isolation test, against a small image
make scan-image-test        # the full end-to-end scan, against the real image
```

The isolation test defaults to `minimal.Dockerfile` — the same entrypoint and the same
profile, without four gigabytes of analysers it does not exercise — so it runs in
seconds on every commit. Point `BASTION_SANDBOX_TEST_IMAGE=bastion-sandbox:latest` at
the real image to run the identical assertions there; they pass, and it costs more.
