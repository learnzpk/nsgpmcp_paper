# An LLM Agent with MCP-Standardized Tooling for Campus Cybersecurity Operations — Design, Deployment, and Evaluation

Evaluation artifact bundle for the manuscript "An LLM Agent with MCP-Standardized
Tooling for Campus Cybersecurity Operations" (manuscript under review). The
manuscript itself is not
redistributed here; see the repository at https://github.com/learnzpk/nsgpmcp_paper.

Everything in this repository is **de-identified for public release**. The
production platform, its configuration, and all ledgers are not distributed.

## Repository layout

```
figures/           Figures 1-4 (PNG, plus SVG sources where available)
artifacts/         Evaluation artifact bundle (masked), described in
                   artifacts/README.txt:
  - task suites:   pilot v1 (24 tasks), production v2 (259 frozen tasks,
                   253-task analysis set), adversarial suite H (20 tasks)
  - run traces:    production v2 (3 arms x 2 passes), pilot traces,
                   cross-model replication (DeepSeek-V4-Flash-0731),
                   adversarial suite H (Qwen3.8-Flash-Next full x3 and
                   guardrail-ablated x3; DeepSeek-V4-Flash-0731 x2)
  - statistics:    v2_stats.json / v3_stats.json / h_summary_v2.json /
                   script_baseline.json / cross_model_dsv4.json
  - scripts:       harness, scorers, statistics and figure scripts
                   (shipped for inspection; re-execution against the
                   production endpoint additionally requires internal
                   credentials that are not distributed)
```

## Masking policy (applied to every release file)

- full IPv4 addresses are kept to their first two octets (`202.195.*.*`);
  CIDR prefixes are ledger-level facts and are retained;
- asset identifiers are reduced to their class prefix (`INFO_*****`);
- campus e-mail domains and campus DNS names are reduced to `***.edu.cn`
  (sub-labels retained where generic), e-mail addresses and account-style
  tokens — including carrier-style accounts whose domain part carries no
  dot (account local-part followed by an at-sign and a carrier abbreviation,
  as found in ledger fields) — to `***@***`,
  mainland mobile numbers and MAC addresses are masked, and staff numbers
  are reduced to `10******`;
- Chinese proper names (departments, colleges, vendor organization names,
  named institutional systems, campus sites), person names in all contexts
  (ledger tables, tool outputs, and transliterations) are masked to `***`,
  party/political-work terms wherever they occur in ledger values (unit
  names, assessment-program titles, activity names, rectification texts)
  are masked to `***`,
  as are the institution's Latin-script abbreviation wherever it occurs
  (including inside third-party SaaS tenant names), province/city
  place names that locate the site, and their pinyin/English spellings;
  generic ledger vocabulary (e.g. "information system"-style category terms
  used by the task templates) and national-scale commercial vendor brands
  are retained;
- endpoint URLs, tokens, and keys are not distributed anywhere in this bundle
  (internal identifiers are required to re-execute against the production
  endpoint, so the scripts are shipped for inspection, not for re-execution).

A final automated scan (full IPv4 / unmasked identifiers / e-mails / mobile
numbers / campus domains / MAC addresses / embedded secrets) is run over the
whole folder before publication.

## Provenance

All numbers in the manuscript were produced by the released harness against
the live production MCP endpoint and the campus LLM gateway during one
production month; scoring was audited and the audit trail is documented in
Section 7.4 and Appendix A.6 of the manuscript.

## License / citation

All rights reserved pending camera-ready; contact the author for reuse beyond
peer review. Citation block will be added at camera-ready.
