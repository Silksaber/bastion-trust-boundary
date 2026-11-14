# How Bastion scores a finding

Every card Bastion shows carries two bands and moves one number: the risk of doing
nothing, the impact of making the change, and your overall security score. This page
describes how each is produced.

It describes the method. The scoring code and its exact weights are not published.
Inside the product, each band opens to show every factor that produced it and the
evidence behind that factor.

## The rule everything else follows

**A language model extracts facts. A deterministic function decides scores.**

| The model does | The model never does |
|---|---|
| Answer narrow factual questions, such as "is this endpoint behind authentication?" | Produce a band, a score or a weight |
| Write the explanation you read | Decide the order of the queue |
| Read code and infer what a service is for | Override a computed value |

The scoring function has no database connection and makes no model call. The same
facts always give the same output. Every stored score records the version of the rubric
that produced it, and changing the rubric never rewrites an old score silently.

This matters for more than tidiness. From the moment Bastion can execute a change, the
impact band helps decide what may run without a person. A band that drifted between
runs would be an authorization decision that drifted between runs.

## 1. Risk of doing nothing

Bands: `very low`, `low`, `moderate`, `high`, `critical`.

Eight factors, each scored 0 to 4, weighted, and normalised to a 0 to 100 scale:

| Factor | What it measures | Where the answer comes from |
|---|---|---|
| Exploitability | How technically easy exploitation is | CVSS vector, and what happened when Bastion tried |
| Exposure | Internet-facing, internal or isolated | Repository analysis, and live cloud state where connected |
| Exploit availability | Whether a public exploit exists | Public exploit sources |
| Threat activity | Whether attackers are using it now | CISA KEV and EPSS |
| Authentication | Whether exploitation needs a login | CVSS, and what happened when Bastion tried |
| Attack complexity | Whether it needs unusual conditions | CVSS, and what happened when Bastion tried |
| Existing controls | Firewalls, segmentation and similar | Live cloud state where connected |
| Asset accessibility | Whether an attacker can reach the component at all | Repository analysis, and live cloud state where connected |

Exposure and threat activity carry the most weight.

| Band | Range |
|---|---|
| very low | 0–19 |
| low | 20–39 |
| moderate | 40–59 |
| high | 60–79 |
| critical | 80–100 |

### The accessibility gate

If the vulnerable component cannot be reached, the whole score is multiplied down,
whatever its CVSS. This is why the queue is not a list sorted by CVSS: a critical CVE
in a container nobody can route to should rank below a moderate flaw on your public
login page.

The gate has two strengths, and which one applies depends on who answered:

- **Measured.** Live cloud state shows the component is unreachable, for example a
  security group that admits one private network. The gate applies at full strength.
- **Inferred.** Only the repository suggests it is unreachable. The gate applies at a
  much reduced strength, because a comment saying "this module is not deployed" is not
  evidence.

The two possible mistakes are not equal. Wrongly calling something unreachable buries a
live vulnerability. Wrongly calling it reachable shows a card a little too high.
Bastion is allowed to understate a mitigation and not allowed to overstate one.

The same reasoning runs the other way for attack paths: finding a path from the
internet to a component can raise its score, and failing to find one never lowers it.

### Rules that hold for every risk score

- **Missing data is not safety.** If a threat feed cannot be reached, the factor is
  marked degraded. It is never scored as zero.
- **A card says what is known.** Each finding carries an evidence state: `exploited`
  only when Bastion reproduced it, `observed` for live account state, and
  `inconclusive` or `unvalidated` otherwise. An unvalidated finding always ranks below
  the same finding confirmed.
- **A demonstrated false positive is never scored and never shown.**
- **The explanation is written for your system.** It says what this service does and
  what an attacker gains here. It is not a pasted CVE description.

### Residual risk

Each card also shows the band after the fix, such as `high → low`. It is the same
function run again on the facts after the fix. It is rarely zero.

A fix is treated as complete only when two things agree: a re-scan no longer finds the
problem, and the assessment of the change says it removes the weakness fully. Either
one alone caps the claim at partial.

## 2. Impact of making the change

Bands: `trivial`, `minor`, `moderate`, `significant`, `transformative`.

This answers "what am I risking by accepting this?"

| Factor | What it measures |
|---|---|
| Reversibility | From a single commit revert up to effectively irreversible |
| Scope | Files, resources, services and environments touched. The largest of these counts, not the average. |
| Type of change | Code is lowest. Configuration is higher. Network, IAM and infrastructure are higher still. Database and architecture are highest. |
| Dependency impact | Dependent services, integrations and downstream systems |
| Behavioural impact | Whether functionality, access, data flow or authentication changes |
| Deployment scope | From development only up to the entire environment |

Type of change and behavioural impact carry the most weight. The bands use the same
ranges as risk.

A fix that breaks known attack paths has its displayed impact reduced, by a capped
amount, because it is a more valuable change to accept. That reduction affects what the
card shows. It never affects what is allowed to run unattended, which is decided from
the change's own facts before any reduction.

### Impact as an authorization boundary

Each customer chooses an autonomy level. The level is expressed in impact bands:

| Level | Runs without a person, up to |
|---|---|
| `shadow` | nothing. Plans are shown and not run. |
| `assisted` | nothing. Every change asks. |
| `supervised` | `minor` |
| `autonomous` | `significant` |

Three limits hold at every level, for every customer, however urgent the risk:

- A `transformative` change never runs unattended.
- An irreversible change never runs unattended.
- A change runs unattended only if the platform itself can undo it, and only after the
  way back and the prior state have been stored.

## 3. Overall security score

One number from 0 to 100, with its change since the last snapshot.

Each open finding adds a penalty set by its risk band, scaled by how important the
affected asset is and by how long the finding has been open. The score falls along a
curve as the total penalty grows.

Properties we hold it to:

- **No score before the first look.** An organization nothing has scanned shows "no
  score yet", not 100.
- **100 means nothing is open, and nothing else.**
- **Neither end saturates.** More findings always score worse than fewer, and every fix
  moves the underlying value.
- **One finding cannot be most of your score.**
- **Unfixed findings cost more as they age.**
- **Declining a risk does not hide it.** An accepted risk still counts, at a reduced
  weight.
- **A card does not promise a change it cannot make.** If a fix is real but too small
  to move the displayed number, or has not been verified yet, the card says so.
- **The number is never recomputed in your browser.** Every screen shows the stored
  result.

## What we test

- Every band boundary, in both models.
- Determinism: repeated scoring of the same facts gives identical output.
- The same CVE in an internet-facing service and in an isolated one gives different
  bands.
- An unreachable critical ranks below a reachable moderate.
- With every threat feed unreachable, scoring still completes and marks what it could
  not learn.
- At each impact band and each autonomy level, `transformative` and irreversible
  changes are never authorized.
