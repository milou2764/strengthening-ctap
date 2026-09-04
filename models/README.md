# Models

Formal models and diagrams supporting the paper.

## `puml/` — PlantUML sequence diagrams

The figures in the paper. Render with [PlantUML](https://plantuml.com/):

```bash
plantuml puml/solution-enroll.puml       # -> solution-enroll.png
```

| File | Figure |
|---|---|
| `solution-enroll.puml` | Enrollment: direct BLE connection + numeric comparison. |
| `solution-authentication.puml` | Authentication: per-session COSE_Sign1 over CTAP hybrid. |
| `ctap-hybrid.puml` | The CTAP hybrid (caBLE v2) transport. |
| `relay-attack.puml`, `bluetooth-relay.puml` | The relay/unauthorized-client threat. |
| `id-federee.puml` | Federated-identity context. |

The rendered `.png` versions live in [`../paper/`](../paper/) because LaTeX
includes them there.

## `promela/` — SPIN / Promela models

Formal models of the protocols, checked with [SPIN](https://spinroot.com/).

| File | Models |
|---|---|
| `model-legitimate.pml` | The nominal (attack-free) ceremony. |
| `model-enrollment.pml` | Enrollment over a direct BLE connection with numeric comparison, against a generative intruder; two authenticators in range. |
| `model-counter-measures.pml` | Per-session client authentication over the hybrid transport, against a generative intruder; two concurrent sessions. |

The intruder in the last two is **not** scripted: it is given knowledge
(advertisements, captured signatures, keys written to its own authenticator) and
construction rules, and may act at any interleaving. SPIN composes the attacks.

**Verify everything at once:** `promela/verify.sh` runs all scenarios (each with
its `-D` switches), checks the named LTL claim with SPIN, and compares the
outcome against what the paper expects, printing `PASS`/`FAIL` (non-zero exit on
any failure). Requires `spin` and a C compiler.

```bash
./promela/verify.sh
```

To run a single scenario by hand:

```bash
cd promela
spin -a model-enrollment.pml       # no -D: code derived from the key alone
cc -O2 -o pan pan.c
./pan -a -N p_binding              # -N selects the LTL claim
spin -t -p model-enrollment.pml    # replay the counterexample
```

### Results (summary)

Authentication (`model-counter-measures.pml`, claim `p_auth` — no unenrolled
client is ever served):

- full countermeasure — holds;
- `-DNO_COUNTERMEASURE` — violated (baseline CTAP);
- `-DNO_FRESHNESS` — violated. SPIN finds the replay itself: the intruder
  captures the signature made in one session and injects it into the concurrent
  session, which a reused advertisement lets through.

Enrollment (`model-enrollment.pml`, claim `p_binding` — a completed enrollment
stored the legitimate client's key):

- `-DCOMMITTED_CODE` (code from both public keys and both committed nonces, as
  in Bluetooth Secure Simple Pairing) — holds, and still holds with
  `-DGLOBAL_CLIENT_KEY`;
- no switch (code derived from the client key alone) — **violated, even with a
  distinct key pair per authenticator**. The client's BLE discovery may reach
  the intruder's authenticator, so the intruder learns the fresh key during the
  ceremony and shows that key's code to the victim's authenticator; the user
  compares two codes belonging to two different pairings;
- `-DGLOBAL_CLIENT_KEY` — violated by a shorter route (no concurrent enrollment
  needed);
- `-DNO_NUMERIC_COMPARISON` — violated, as expected.

The violated control is the point: what the property needs is a code that no
participant can **bias**, not one the adversary cannot know.

`verify.sh` also re-runs each model with its LTL claims stripped, so SPIN checks
for invalid end states (deadlock-freedom).
