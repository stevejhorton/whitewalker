# steve_to_review: what moved and why

Nothing here was deleted. Review by hand, then delete what you do not want. None of it is used at runtime.

| Item | What it is | Covered by | Suggest |
|---|---|---|---|
| `docs_archive/` | 13 old ER/RC fix notes | Current code, README.txt history, SPEC_BUILD_BRIEF | Safe to delete |
| `CPR_RC_1.13_Info.md` | RC1.13 info | README.txt history | Safe to delete |
| `CPR_ER6_Info.docx` | ER6 info | Superseded | Safe to delete |
| `COMPLETE_TEST_SUMMARY.md` | Old test summary | Tests in `tests/` | Keep if you want the old counts |
| `CPR_Master_Test_Doc.zip` | Old master test doc | `CPR_Test_Plan.md` | Keep until the test plan is refreshed |
| `unit_test_results_10jun26.txt` | Your June Pester run (v5.3.3) | Cited in SPEC_BUILD_BRIEF | Keep (only proof of a live run) |
| `talking_points.txt` | Old talking points | None | Keep if still useful |
| `drawio_backups/` | Editor autosave backups | The live .drawio files | Safe to delete |
| `code_archive/` | Old tests, old WW_main monolith, log.txt.xml | Current tree and git history | Safe to delete (git keeps it) |
| `logs_samples/` | One unlock diag log and popup.png | n/a | Safe to delete |
| `CPR+ _ WhiteWalker Capability and Use Case Breakdown.pdf` | Previous (RC1.19) PDF render | New PDF in docs/ | Safe to delete |

## Open questions for you
- `cpr_user_guide.html` and `vpn_blackhole_info.html` still contain [PLACEHOLDER] contacts (emails, phone, access page). I cannot invent these; please supply real values.
- `townhall_slide.html` claims (97.4% test pass, 99%+ remediation, 2-3M executions/day, 90% reduction) are unverified. Confirm or remove.
- `CPR_Test_Plan.md` and the three `.drawio` files predate RC2; they have not been re-verified.
- `support_files/More-Sense_testing.ps1` was left in place because WW_xml_vault.ps1 refers to it.

## Retired tests
- `RC1.25.Package.Tests.ps1.obsolete` - guarded the RC1.25 package directory name and version markers. This release is RC2.0.2, so it could never pass; version consistency is enforced by `CPR_RC2.Main.Tests.ps1` and `CPR_RC2.BuildIdentity.Tests.ps1`. Moved here (not deleted) on 2026-10-28.
