# Internal references in the published files

The files in this repository are copied unchanged from the private product repository,
so their comments mention internal documents. This page says what each reference means.
The documents themselves are not published.

## Documents

| Reference | What it is |
|---|---|
| "the brief", `product-description.md` | The product's founding description. It commits Bastion to running all scanning on its own infrastructure, never on a customer's machine. |
| `DECISIONS.md`, `ADR-nnn` | The log of architecture decisions. The ones cited here are summarised below. |
| `ARCHITECTURE.md` | The internal architecture description, including the table of trust boundaries. |
| `CLAUDE.md` | The repository's working rules for contributors. It lists the invariants no change may break, including "the remediate role can only tighten". |
| `docs/evidence/...` | Stored output from rehearsals against real cloud accounts. |
| `docs/cloud-delivery.md` | A generated table saying, rule by rule, whether a cloud finding can be fixed by the product or is handed over as guidance. |

## Stages

`Stage n` is a numbered build stage of the product. The ones that appear here:

| Stage | What it built |
|---|---|
| Stage 1 | Accounts and the separation between customer organizations. |
| Stage 2 | The GitHub App connection. |
| Stage 3 | Scanning inside the sandbox. |
| Stage 4 | The agents that confirm a finding, which is when the sandbox began running customer code on purpose. |
| Stage 5 | Scoring. |
| Stage 6 | Pull-request analysis. |
| Stage 7 | Read-only cloud observation. |
| Stage 8 | Changes executed in a customer's cloud account. |
| Stage 10 | Hardening before the first customers. |
| Stage 11 | Attack-surface monitoring and attack paths. |

`Operation Cloud Stage n` is a later hardening pass over the cloud features, and
`issue Cnn` is an item from its audit list.

## Decisions cited

| Decision | What was decided |
|---|---|
| ADR-003 | A language model extracts facts and writes explanations. A deterministic function turns facts into scores. The model never produces a band, a weight or an ordering. |
| ADR-004 | The scan sandbox is a container with no network namespace at all, not a container behind a network policy. There is no interface to misconfigure. |
| ADR-009 | Sandbox isolation is proved by running a hostile repository against it in CI on every commit, not by reviewing configuration. |
| ADR-013 | Cloud security is part of the first release, partly because live cloud state makes the reachability of code findings a measurement, not a guess. |
| ADR-015 | The platform executes changes in customer accounts, through a role that can only tighten. A fix that would need a granting action is delivered as a pull request or as steps for a person. This is what limits the worst case of a platform compromise to over-restriction. |
| ADR-031 | A rollback has one of three modes. `platform`: the inverse is itself a tightening action, so the platform can undo the change. `customer`: the inverse is known and stored exactly, but needs an action the role will never hold, so a person runs it. `none`: nothing can undo it, such as a deleted access key. Only `platform` changes may run unattended. The inverse and the prior state are stored before anything is applied, in all three modes. |
| ADR-032 | After a change, the account is re-read through the observe role. The remediate role holds no read action. |
| ADR-048 | One template can create both AWS roles at once. They remain two roles with two external IDs, each revocable alone. |
| ADR-050 | The sandbox image ships language interpreters and no package manager. Installing dependencies would execute install scripts chosen by the repository being examined. |
| ADR-056 | Where a cloud finding can be fixed in the Terraform that declares the resource, the product prepares that change as a pull request. Nothing is applied by the platform. |
| ADR-057 | Whether a change landed is decided by re-reading the account, never by trusting an API response, and only one operation may hold a resource at a time. |
| ADR-067 | The system-understanding feature. It added inventory-only reads to the observe role, such as load balancers, DNS zones and container services. |
