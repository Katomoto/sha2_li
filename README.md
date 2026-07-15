# Reproducing Li et al.'s SHA-256 Collision Vectors

This repository contains a compact reproduction harness for the SHA-256 parts of
Li et al., *New Records in Collision Attacks on SHA-2*.

The code verifies the paper's concrete published SHA-256 outputs:

- Table 5: practical 39-step SHA-256 semi-free-start collision.
- Table 13: practical two-block 31-step SHA-256 collision.
- Table 25: 39-step SHA-256 semi-free-start collision used in the quantum attack section.

The implementation is intentionally dependency-free. It implements the reduced
SHA-256 compression function, message expansion, feed-forward, and a small CLI
that recomputes the paper's hashes from the published message words.

## Run

```bash
python3 reproduce_sha256.py
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
python3 search_sha256.py check-table13-conditions
python3 search_sha256.py char-search --rounds 12 --shape single --single-word 5 --paper-objective
python3 search_sha256.py char-search --rounds 31 --shape 31 --paper-objective --timeout-ms 600000
python3 search_sha256.py char-search --rounds 39 --shape 39 --paper-objective --timeout-ms 600000
python3 search_sha256.py msgmod-solve-table13 --timeout-ms 600000
```

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
  bit conditions for the 31-step SHA-256 attack and checks them against the
  published Table 13 collision.

## Scope

This repository reproduces both the published SHA-256 collision instances and
the SAT/SMT machinery needed to search for signed differential characteristics
and message-modification constraints. The 31-step and 39-step full searches are
large solver jobs, matching the paper's use of many threads and long-running
experiments; the included tests focus on deterministic checks that finish quickly.
