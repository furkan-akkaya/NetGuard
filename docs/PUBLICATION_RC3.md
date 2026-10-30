# NetGuard 1.0.0rc3 publication

RC3 supersedes the unpublished RC2 draft. The existing RC2 tag is preserved.
The final package review found no upstream license notices in the minified dashboard.
RC3 includes the complete notices for the locked frontend dependencies and type declarations.
Every dashboard build regenerates `THIRD_PARTY_NOTICES.txt` from the installed locked dependency set.
A missing upstream license file fails the build. Vite copies the notice into the packaged static directory.
The source archive includes both the notice and its generator.

The [baseline decision](BASELINE_INTERVALS.md), [confidence review](CONFIDENCE_REVIEW_RC2.md),
[RC2 validation](PUBLICATION_RC2.md) and [unexecuted field plan](FIELD_VALIDATION_PLAN.md) still apply.
No detection threshold, dependency version or runtime algorithm changed between RC2 and RC3.
Python tests, quality checks, frontend checks, audits and packaging gates run again on the final RC3 commit.
The downloaded RC3 wheel must contain the notice before publication.

The strongest objection to stable 1.0 remains missing long and repeated live field measurements.
This version remains an RC. Confidence scores remain heuristic, not attack probabilities.
Linux/macOS resource limits, fixed-window blind spots and lack of fragment reassembly remain unchanged.

Upgrade and rollback follow [DEPLOYMENT.md](DEPLOYMENT.md) and [the RC2 instructions](PUBLICATION_RC2.md#upgrade-and-rollback),
using the RC3 wheel and matching RC3 requirements. There is no database schema change.
Final commit IDs, CI URLs and downloaded asset digests are recorded in the publication report.
