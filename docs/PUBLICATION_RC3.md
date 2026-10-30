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

## Publication record (30 October 2026)

The repository became public after a full-history secret scan (gitleaks, all refs: no findings),
a scan of pull request text, comments and all Actions logs (no findings), and the local gates above.
Raw lab captures were never committed; they stay private, and the old lab-bridge token in them should still be rotated.

| Item | Value |
|---|---|
| Tag | `v1.0.0rc3` (SSH-signed) → merge commit `fa42538` (PR #12) |
| CI on `fa42538` | run 41078135598: 11/11 jobs green |
| Release workflow | run 41078517708: build and draft release green |
| Release | https://github.com/furkan-akkaya/NetGuard/releases/tag/v1.0.0rc3 (pre-release) |

Downloaded asset SHA-256 (also in the release's `SHA256SUMS`; checked again without authentication after publication):

```text
0688783ab74a341bdf267b33c595f4b3f058c10cd461a6ac99c2d95b585f4d31  netguard-1.0.0rc3-py3-none-any.whl
324be4a34034217f20c5fbfd0b4a4413949f2cda48cf1afbda37bb60429f8437  netguard-1.0.0rc3-requirements.txt
6ad62781f9921892e7ca06874e1583296d32204b6e5c13e4abd9f9aafc1059f4  netguard-1.0.0rc3.tar.gz
5cfc157f2d9a8f5ac9c2196675b3440c71d283c321ffa92c04750d6eb8f3fcf6  netguard-sbom.cdx.json
```

No new live experiment was possible in this session (lab VMs stopped, no guest sudo session).
The RC2 release stays an unpublished draft; its tag is unchanged.
