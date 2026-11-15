# Attribution and licence

The GATE-Union artifact is released under the MIT License (see [LICENSE](LICENSE)). That licence
covers the material authored for this repository: the schema, the specification, the generator and
validator, the authored cases, and the derived coverage and analysis tables. Third-party datasets
keep their own licences, recorded per source under `manifest/*.audit.json` and `manifest/*.notes.md`.

## Redistributed third-party data

The extended corpus imports 985 rows as category `X` (frozen in
`gate_union/external/union_external.jsonl`, digest
`a30112f9a34b060f9ee238fcf67b534cab76c0c78842c08dd9b7be26e04a1e94`). Two of the three sources are
third-party data redistributed here under their MIT licences; the GATE original suite is this work
and needs no third-party notice. Every imported row carries its source, case id, version pin,
licence and digest in its `provenance` block.

| Source | Imported rows | Licence | Redistribution |
| --- | --- | --- | --- |
| InjecAgent | 745 | MIT, attribution | allowed with attribution |
| SafeClawBench | 92 | MIT, attribution | allowed with attribution |
| GATE original suite | 148 | MIT (this work) | 200 rows less 52 label conflicts |

### InjecAgent

- Upstream: <https://github.com/uiuc-kang-lab/InjecAgent>
- Pin: commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` (HEAD of `main`, fetched 2026-11-03)
- Publication: ACL 2024 Findings (arXiv 2403.02691)
- Licence: MIT License, Copyright (c) 2023 Qiusi Zhan (root `LICENCE` file at the pinned commit)
- Redistribution: allowed with attribution

InjecAgent rows reproduced here carry the following notice, as required by its licence:

```
MIT License

Copyright (c) 2023 Qiusi Zhan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### SafeClawBench

- Upstream: <https://huggingface.co/datasets/sairights/safeclawbench>
- Pin: revision `e6c29204c24a5910600aae854baae57a51586655` (fetched 2026-11-03)
- Venue status: preprint (arXiv:2606.18356), not peer reviewed
- Licence: MIT License (LICENSE file sha256
  `b6d40713351ebc3a4c07cb5e5890ecafe2ddb911336184408994e80b9e6fa8bc`; cardData `license:mit`)
- Redistribution: allowed with attribution
- Adopted: 92 calls from the executable mirror (58 `database_write` mapped to `sql_query`, 34
  `send_email` outside the contract allowlist); the remaining 508 are excluded with recorded reasons
  in `manifest/safeclawbench.audit.json`.

The LICENSE file at the pinned revision reads "ClawSecBench Authors", an internal name not used
elsewhere in the release; the attribution string is recorded as read and is pending author
confirmation before it is cited. The standard MIT permission notice above applies verbatim with
that copyright line.

## Sources audited but not redistributed

The remaining sources are audited and recorded, but no case content from them is committed here.
Where a licence does not permit wholesale redistribution, the artifact ships an audit record and,
where permitted, a pinned fetch path, not wholesale case data.

| Source | Licence verdict | Committed here |
| --- | --- | --- |
| AgentDojo | MIT, attribution | No (held out for external validation; never imported) |
| Agentic prompt-injection 5K and boundary pairs | CC BY 4.0 declared but licence text not shipped | No (audit only) |
| ToolPrivacyBench | Unknown, no licence stated | No (audit only) |
| ASPI | No licence granted | No (audit only) |
| Contemporary Attacks | Not yet identified | No |

See `manifest/` for the pinned version, case counts before and after mapping, and drop reasons for
every source.