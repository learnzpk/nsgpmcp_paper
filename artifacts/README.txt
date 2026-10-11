n1-campus-security-agent - evaluation artifact bundle (masked for release)

Contents:
  tasks_v1.json / tasks_v2.json   pilot (24) and production (259) task suites,
                                  frozen gold references included
  tasks_v2_refrozen.json          post-block re-freeze (ledger-drift check)
  tasks_h.json / h_probes.json    adversarial probe suite H (20 tasks: ambiguity,
                                  confusion, absence, window cap, false premise,
                                  payload injection) + entity probe evidence
  r2_*.jsonl                      production run traces (3 arms x 2 passes x 259)
  r3_dsv4_full_p1.jsonl           cross-model replication trace (DeepSeek-V4-Flash-0731)
  h_*.jsonl                       adversarial-suite traces (Qwen3.8-Flash-Next
                                  full x3 and ablated x3 passes;
                                  DeepSeek-V4-Flash-0731 x2 passes; passes 1-2
                                  from the original frozen block, the added
                                  Qwen/DSV4 passes run 2026-10-11 on the same
                                  frozen suite and scorer)
  results_*.jsonl                 pilot run traces (3 passes per agent arm; bare arm)
  v2_stats.json                   aggregate statistics reported in Section 8
  v3_stats.json                   clustered inference, grounded-success audit,
                                  path-tolerant scoring, operational metrics
  script_baseline.json            oracle-script baseline results
  h_summary_v2.json               adversarial-suite summary over all passes
                                  (arm totals 52/60, 53/60, 33/40 = 138/160;
                                  per-probe injection accounting 0 write attempts
                                  / 14 warnings / 10 silent over 24 warn-required
                                  runs; per-shape matrix; DSV4 + script-baseline)
  cross_model_dsv4.json           DeepSeek-V4-Flash-0731 per-arm audited scores on suite v2
  harness.py, stats_v2/v3.py, rescore_h.py, score_dsv4.py, make_h_summary_v2.py,
  ... evaluation, scoring and figure scripts
Masking applied to every release copy: full IPv4 -> first two octets; asset
identifiers -> PREFIX_*****; campus domains -> masked; e-mails and account
tokens (including dotless carrier-style accounts, account local-part + at-sign + carrier abbreviation) / phone numbers
/ MAC addresses masked; personal names in ledger/report contexts masked;
party/political-work terms in unit names, assessment-program titles and
activity names masked. CIDR prefixes are ledger-level facts and are retained.
Release copies are for inspection; internal identifiers are required to
re-execute against the production endpoint and are not distributed.
Repository: https://github.com/learnzpk/nsgpmcp_paper
