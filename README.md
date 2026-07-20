# Reproducing Li et al.'s SHA-256 Collision Vectors

This repository contains a compact reproduction harness for the SHA-256 parts of
Li et al., *New Records in Collision Attacks on SHA-2*.

Using the 2024 conference paper as the default baseline, the code verifies its
concrete published SHA-256 output:

- Table 5: practical 39-step SHA-256 semi-free-start collision.

Journal-extension-only artifacts from the later expanded version are still kept
in the repo, but they are no longer the default:

- Table 13: practical two-block 31-step SHA-256 collision.
- Table 25: 39-step SHA-256 semi-free-start collision used in the quantum attack section.

The implementation is intentionally dependency-free. It implements the reduced
SHA-256 compression function, message expansion, feed-forward, and a small CLI
that recomputes the paper's hashes from the published message words.

## Run

```bash
python3 reproduce_sha256.py
python3 reproduce_sha256.py --paper all
```

Expected result: every vector prints `PASS`, and the computed left/right hashes
match the hash printed in the paper.

To inspect the paper-style signed bit differences for a vector:

```bash
python3 reproduce_sha256.py --trace table5
python3 reproduce_sha256.py --trace table13
python3 reproduce_sha256.py --trace table25
```

## Test

```bash
python3 -m unittest discover -s tests
```

## SAT/SMT Search Pipeline

Install the optional solver dependency before running search commands:

```bash
python3 -m pip install -r requirements.txt
```

Useful entry points:

```bash
python3 search_sha256.py char-search --rounds 12 --shape single --single-word 5 --paper-objective
python3 search_sha256.py char-search --rounds 31 --shape 31 --paper-objective --timeout-ms 600000
python3 search_sha256.py char-search --rounds 39 --shape 39 --paper-objective --timeout-ms 600000
python3 search_sha256.py check-table13-conditions
python3 search_sha256.py msgmod-solve-table13 --timeout-ms 600000
```

To inspect which double-bit conditions are implied by a SHA-2 Boolean-function
transition under signed differences:

```bash
python3 enumerate_sha2_boolean_conditions.py --function if --pattern u===
python3 enumerate_sha2_boolean_conditions.py --function all --format json
python3 enumerate_sha2_component_conditions.py --component sigma1 --output-bit 19 --pattern 'n==u'
python3 enumerate_sha2_component_conditions.py --component addition --pattern '==nn='
python3 extract_fig6_conditions.py
python3 extract_fig6_conditions.py --show-components --component Sigma1 --round 7
python3 extract_fig6_conditions.py --show-additions --equation W --round 22 --bit 19
python3 check_fig6_conditions.py --skip-full-model
```

`extract_fig6_conditions.py` is the pure symbolic path: it reads only the
Fig. 6 signed-difference patterns, resolves component outputs through complete
local `W_i`, `E_i`, and `A_i` equations, and then queries the `IF`, `MAJ`,
`Sigma0`, `Sigma1`, `sigma0`, `sigma1`, and exact full-adder condition tables.
Conditions are retained only when every equation-compatible output/carry branch
implies them. The published collision pair is not used by this extraction; it
is used only by `check_fig6_conditions.py` for independent regression
validation.

`char-search` now follows Algorithm 1 from the paper directly. The switches
`--op1` through `--op8` control fast/full Boolean models, Method-1/Method-2
expansion models, and whether the `SHA2-W` part is included.

The SAT/SMT code has two layers:

- `sha256_reduced.smt_characteristic` implements the pure signed-difference
  model with the paper's `(v, d)` encoding and the 27-rule modular-addition
  table from Table 2. Component propagation is added as CNF clauses generated
  from the legal propagation rows, matching the paper's LogicFriday-style
  modeling flow.
- `sha256_reduced.smt_value` implements the value-transition model used for
  message modification and conforming-pair search.
- `sha256_reduced.conditions` encodes the 164 Table 14/15 message-modification
  bit conditions for the journal-extension 31-step SHA-256 attack and checks
  them against the published Table 13 collision.

## Scope

This repository now defaults to the 2024 conference paper you selected, while
still retaining journal-only SHA-256 vectors and message-modification material
from the later expanded version. The 31-step and 39-step full searches remain
large solver jobs, matching the paper's use of many threads and long-running
experiments; the included tests focus on deterministic checks that finish quickly.
