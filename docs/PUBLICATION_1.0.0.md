# NetGuard 1.0.0 publication

1.0.0 is the first stable release. Its code is RC3's; only versions and documentation changed.
The stable claim rests on the executed [field validation](FIELD_VALIDATION_RC3.md), which met every preregistered expectation of the [plan](FIELD_VALIDATION_PLAN.md).
The [baseline decision](BASELINE_INTERVALS.md), [confidence review](CONFIDENCE_REVIEW_RC2.md) and [RC3 notices](PUBLICATION_RC3.md) still apply.
Checklist row 2 stays partly met for its documented limits, so the release does not claim complete Definition-of-Done compliance ([RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)).

## Publication record (31 October 2026)

| Item | Value |
|---|---|
| Release PR | #14 (head `c01c081`): CI 11/11 jobs and release dry-run green |
| Merge commit | `ba66c0f` |
| CI on `ba66c0f` | [run 41167456873](https://github.com/furkan-akkaya/NetGuard/actions/runs/41167456873): 11/11 jobs green |
| Tag | `v1.0.0` (SSH-signed, verified locally) → `ba66c0f`; earlier tags unchanged |
| Release workflow | [run 41167621976](https://github.com/furkan-akkaya/NetGuard/actions/runs/41167621976): build and draft release green |
| Release | https://github.com/furkan-akkaya/NetGuard/releases/tag/v1.0.0 (stable, latest) |

Downloaded asset SHA-256 (also in the release's `SHA256SUMS`; checked again without authentication after publication):

```text
ae052e7bf527b23ee80fac2445a825c0b91d88988065bba4c3776943b94055da  netguard-1.0.0-py3-none-any.whl
00ded88f19088ab0d9e5dd80adcab4c54c3d3b85f18dc6da7b211a78f99a44fb  netguard-1.0.0-requirements.txt
344671ac0eba3ca1994ba13e408dac26ce0a1887249742a26a49ab647502c14a  netguard-1.0.0.tar.gz
a7ba2c787d484d34a047f6756cdf4a5c0e754e94b458e12ea0609efe0c0d09b7  netguard-sbom.cdx.json
```

Checks on the downloaded draft before publication:

- Wheel and sdist carry version 1.0.0 and `THIRD_PARTY_NOTICES.txt`; the sdist holds no capture files.
- The SBOM lists 15 components.
- A clean virtual environment installed the wheel with the locked requirements; `release_checks.py installed` passed.
- The installed package printed `netguard 1.0.0` and gave the synthetic scorecard TP=20, FP=3, FN=1.
- Analysing the private `exp14-rate-volume-r03` capture gave exactly NG-RATE-001 and NG-VOL-001.

## Lab access after the field run

The bridge token files on both VMs were deleted with owner approval, and no bridge service runs, so the token in old raw captures is accepted nowhere.
The old raw captures still stay private.
`/etc/sudoers.d/ng-lab` was removed from both VMs after the runs; `sudo -n` now requires a password on both.
SSH stays enabled at the owner's request.

Upgrade and rollback follow [DEPLOYMENT.md](DEPLOYMENT.md) and [the RC2 instructions](PUBLICATION_RC2.md#upgrade-and-rollback), using the 1.0.0 wheel and matching requirements.
There is no database schema change.
