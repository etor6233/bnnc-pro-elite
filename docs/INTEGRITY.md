# Integrity principles

1. **Every discontinuity is a typed GAP with an exact reason.**
   `unprovable_continuation`, `transport_dead`, `exchange_silent` — counted, auditable,
   declared in the canonical journal. Silent loss is the only forbidden outcome.

2. **Fabricating zero gaps is forbidden.** The historical replay contains 5 typed gaps and
   5 rebootstrap per symbol. They are preserved, visible and reproduced identically by both
   verifier implementations — evidence beats cosmetics.

3. **Two independent implementations must agree byte-for-byte.** Rust and Python verifiers
   implement the same contract from scratch; reports reconcile with identical SHA-256
   (`evidence/g2-reconciliation.json`).

4. **Nothing enters without red-green tests and clean qualification.** Every fix lands with a
   failing test first; every tool/script is qualified in a clean workspace before promotion;
   failures are preserved as evidence, never deleted.

5. **No speculation without a refutation criterion.** Every phase of the roadmap advances only
   on evidence produced by the previous phase (see governance loop in docs/ROADMAP.md).

6. **Historical evidence is immutable.** Journals, holdout and failure artifacts are never
   rewritten; new runs produce new evidence directories.
