# Bastion trust boundary

Bastion by Silksaber is a hosted security engineer for small and mid-sized companies.
To do its job it asks for access to your cloud account, your GitHub repositories and
your source code. This repository holds the files that decide what that access can do,
so you can read them before you grant anything.

**Bastion as a whole is not open source.** The parts that find, confirm and fix problems
are proprietary. What is published here is the boundary around them: the permissions we
ask for, the checks that stop those permissions growing, and the sandbox your code runs
in.

## What you can check here

| Your question | Read this |
|---|---|
| What can Bastion read in my AWS account? | [`infra/aws/observe-policy.json`](infra/aws/observe-policy.json). Every action is a `Get`, `List` or `Describe`, with one named exception that asks AWS for a report it already keeps. [`scripts/check_cloud_observe_permissions.py`](scripts/check_cloud_observe_permissions.py) fails our build if any other kind of action appears. |
| What can Bastion change in my AWS account? | [`infra/aws/remediate-policy.json`](infra/aws/remediate-policy.json). Six actions. Each one closes, revokes, deletes, detaches or encrypts. |
| What can Bastion never do, even if Bastion itself is breached? | Grant access, widen a policy, open a port or create an identity. The role does not hold those actions, and [`scripts/check_remediate_policy.py`](scripts/check_remediate_policy.py) fails our build if one is ever added. |
| What exactly does each change call, and how is it undone? | [`packages/cloud/src/bastion_cloud/remediate/steps.py`](packages/cloud/src/bastion_cloud/remediate/steps.py). Every change as literal API calls, with its inverse and who is able to run that inverse. |
| What do I deploy to connect? | The CloudFormation and Terraform in [`infra/aws/`](infra/aws/) and [`infra/gcp/`](infra/gcp/). They are the templates the product hands you. |
| What can Bastion read in my Google Cloud project? | [`packages/cloud/src/bastion_cloud/gcp/services.py`](packages/cloud/src/bastion_cloud/gcp/services.py) lists the permissions for each service you select. There is no write grant for Google Cloud. |
| What can the GitHub App do to my repositories? | [`infra/github/app-manifest.json`](infra/github/app-manifest.json). [`scripts/check_github_permissions.py`](scripts/check_github_permissions.py) fails our build if it gains administration, workflows, actions or secrets. |
| What happens to my source code on your machines? | It is scanned inside the sandbox described in [`infra/sandbox/`](infra/sandbox/). The isolation flags are in [`profile.py`](apps/worker/src/bastion_worker/sandbox/profile.py) and the syscall allow-list is [`seccomp.json`](infra/sandbox/seccomp.json). |
| How do you know the sandbox holds? | [`fixtures/adversarial-repo/`](fixtures/adversarial-repo/) is a repository built to escape it. [`test_sandbox_isolation.py`](apps/worker/worker_tests/test_sandbox_isolation.py) runs it on every commit and fails if any attempt succeeds. |
| How is a risk band decided? | [`docs/SCORING-METHOD.md`](docs/SCORING-METHOD.md). |

## Check it yourself

You do not have to take this repository's word for what you granted. AWS will show you
the roles as they exist in your account:

```sh
aws iam get-role-policy --role-name BastionObserveRole   --policy-name BastionObserveReadOnly
aws iam get-role-policy --role-name BastionRemediateRole --policy-name BastionRemediateTightenOnly
aws iam get-role --role-name BastionRemediateRole --query Role.AssumeRolePolicyDocument
```

Those are the default role names. Compare the output with the two JSON files above.
Your CloudTrail records every time either role is assumed.

To run the checks and tests in this repository:

```sh
python scripts/check_remediate_policy.py
python scripts/check_cloud_observe_permissions.py
python scripts/check_github_permissions.py

pip install -r requirements-test.txt
pytest packages/cloud/cloud_tests      # the JSON, CloudFormation and Terraform agree
pytest -m sandbox                      # the escape suite; needs Docker
```

## How this repository is produced

It is a one-way export from the private product repository. Every file listed under
`verbatim` in [`EXPORT.json`](EXPORT.json) is a byte-for-byte copy of the file the
product uses, at the same path, with its SHA-256. Nothing is rewritten for publication.

Three consequences of copying without editing:

- **Comments refer to things you cannot see.** `ADR-015`, `Stage 8`, `CLAUDE.md` and
  similar are internal design records and build stages.
  [`docs/INTERNAL-REFERENCES.md`](docs/INTERNAL-REFERENCES.md) says what each one means.
- **Some paths point at files that are not here**, such as the API service that derives
  the external ID. They exist in the private repository.
- **The scanner image does not build from this repository alone.**
  [`infra/sandbox/Dockerfile`](infra/sandbox/Dockerfile) copies two directories that are
  not published: our own detection rules and a code-structure extractor.
  [`minimal.Dockerfile`](infra/sandbox/minimal.Dockerfile) does build, and it is the
  image the escape suite runs against: the same entrypoint and the same isolation
  profile, without the scanners.

Files listed under `public_only` exist only here: this README, the licence, the
documents in `docs/`, and two small import shims that say so in their first line. The
shims let the published sandbox code run without the unpublished packages around it.

## What this repository cannot tell you

- **It does not prove what is running.** Published source shows how the boundary is
  designed and tested. It cannot show that our servers run exactly these files.
- **It does not cover where your code is sent for analysis**, which model provider
  receives it, or how long anything is kept. Those are facts about how we operate, and
  source code cannot establish them. Ask us for them in writing.
- **It does not cover separation between customers.** That control is spread through
  the application and is not published.
- **Active testing (pentest) has its own network boundary**, which is not published yet.

## Reporting a security problem

See [`SECURITY.md`](SECURITY.md). Please do not open a public issue for a vulnerability.

## Licence

Apache License 2.0. See [`LICENSE`](LICENSE). You may copy the policies, the templates
and the sandbox profile into your own work.
