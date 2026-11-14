# Reporting a security problem

If you find a way to break anything this repository describes, we want to hear it
before anyone else does. That includes:

- an action in either AWS policy that can be used to grant access, widen a policy, open
  a port or create an identity;
- a way out of the scan sandbox, or a way for sandboxed code to reach a network, a host
  path or a credential;
- a GitHub App permission that allows more than this repository says;
- a difference between a file here and what the product hands you or deploys in your
  account.

## How to report

Use **Report a vulnerability** under this repository's **Security** tab. It opens a
private report that only the maintainers can read.

Please do not open a public issue or pull request for a vulnerability, and please do
not test against Bastion's hosted service or another customer's account. Everything in
this repository can be exercised locally: the checks run with Python alone and the
escape suite runs against a local Docker daemon.

## What to include

- The file and line, or the policy action, the report is about.
- What you did and what happened, in enough detail to repeat it.
- What an attacker gains.

## What happens next

We acknowledge a report within three working days and tell you whether we can
reproduce it. We tell you when a fix is deployed, and we credit you in the fix unless
you ask us not to.

## Scope

In scope: every file listed under `verbatim` in `EXPORT.json`.

Out of scope here: the rest of the Bastion product, which is not published. If you
believe you have found a problem in the hosted service, report it the same way and say
so.
