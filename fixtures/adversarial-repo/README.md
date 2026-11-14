# adversarial-repo

A repository crafted to escape the sandbox. It is scanned like any other repository,
and its own scripts are executed inside the sandbox — which is the honest model of the
threat, because from Stage 4 the validator agent runs customer code deliberately.

Every file in `attacks/` prints exactly one line per attempt:

```
bastion-escape-check <name> BLOCKED <why> | SUCCEEDED <what got through>
```

The test asserts three things, and the third is the one that catches rot: no line says
`SUCCEEDED`, every expected check name appears, and the job is killed at its cap rather
than running forever. A check that silently failed to run must not be mistaken for a
check that passed.
