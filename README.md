# SeverityResolver: a rubric-bound resolution primitive for GenLayer

## Purpose
A reusable contract that turns a subjective judgment ("how severe is this report?", "was this milestone met?") into an on-chain decision **without letting the LLM decide the outcome**. The LLM only answers a fixed checklist of yes / no questions about evidence. The final label comes from deterministic rules stored on-chain. Other contracts can read `get_case` for the settled label.

First use case: classifying security-report severity against a published rubric (see `example_rubric.json`). Swap the rubric for grants, contests, or escrow conditions.

## How consensus is used
1. `resolve(case_id)`: the leader fetches each allowlisted evidence URL (`gl.nondet.web.render`), then asks the LLM the checklist (`gl.nondet.exec_prompt`).
2. The leader's output is parsed strictly and reduced to a canonical JSON of `{question_key: yes|no}`.
3. `gl.eq_principle.strict_eq` makes validators reproduce **that exact object**. Prose, wording and ordering differences between LLM runs cannot cause disagreement. Only a real difference in judgment can.
4. The label is derived deterministically from the agreed answers (first matching rule wins).

Why strict equality over a tiny object: it is the most defensible equivalence rule. Nothing subjective is left for validators to be "close enough" on, and binary answers (yes = explicitly established, no = anything else) avoid the no-vs-unclear ambiguity that splits validators running different LLMs.

## State design
`OPEN -> RESOLVED -> FINAL`, with one optional appeal (`RESOLVED -> FINAL`, re-fetches evidence and re-runs the checklist; the new result replaces the old one, and `overturned` records whether it changed).

| Storage | Content |
|---|---|
| `rubrics` | immutable rubric JSON (questions, ordered rules, default) |
| `cases` | JSON: rubric_id, subject, urls, opener, state, answers, label, initial_label, appealed, overturned |
| `allowed_hosts` | owner-managed exact-match hostname allowlist |

## Hardening
- Subject text and fetched pages are treated as untrusted and fenced in the prompt. Output keys outside the rubric are dropped, so an injected `"severity":"critical"` has no effect (tested).
- Only an explicit "yes" counts as established. Everything else is "no". Collapsing "no" and "unclear" into one value removes the main source of validator disagreement.
- URLs: https only, exact host allowlist, no userinfo, no ports (blocks `github.com.evil.com`, `evil.com@github.com`, etc.).
- Input size caps on everything. Rubrics are validated on registration (unknown keys, empty rules, contradictory rules rejected).
- Malformed LLM output fails the transaction and leaves the case `OPEN` so it can be retried.

## Known limitations
- Evidence is fetched live and not snapshotted. If a page changes between `resolve` and `appeal`, the result can change (that is what the appeal is for). Hashing evidence on-chain would break validator agreement on dynamic pages.
- No time-based challenge window. Appeal and finalize are explicit actions by the opener or owner.
- The owner controls the host allowlist and rubric registration.
- Quality depends on rubric questions being concrete and checkable from the evidence.

## Run the tests (local, GenVM stubbed)
```
pip install pytest
pytest -q
```
The local tests cover rubric validation, rule evaluation, parsing and injection handling, URL hardening, access control and the full state machine.

## Deploy
1. The first line pins the GenLayer runner hash copied from GenLayer Studio. If Studio shows a newer one, update it.
2. Deploy `severity_resolver.py` in Studio, then call: `allow_host("github.com")`, `register_rubric("sev", <example_rubric.json contents>)`, `open_case(...)`, `resolve(...)`.

## Tuning notes (from live testing)
Validators run different LLMs. With a three-way yes/no/unclear answer they disagreed (UNDETERMINED) on borderline questions, so answers are binary and prompts say "yes only if explicitly established". If a case is still UNDETERMINED, make the rubric questions more concrete and tied to wording that appears in the evidence, or use an evidence page that states the facts plainly.
