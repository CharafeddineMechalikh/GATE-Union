# Attribution and licence

The GATE-Union artifact is released under the MIT License (see [LICENSE](LICENSE)). That
licence covers the material authored for this repository: the harmonisation schema, the
specification, the scripts, the authored stateful set, and the derived coverage and analysis
tables. Third-party datasets keep their own licences, recorded per source under
`manifest/*.audit.json` and `manifest/*.notes.md`.

## Redistributed third-party data

Only one external source contributes redistributed case content to this repository, and that
is **InjecAgent** (`harmonized/injecagent.jsonl`, `harmonized/injecagent.excluded.jsonl`, and the
InjecAgent rows carried into `splits/`). The GATE original suite and the authored set are this
work and need no third-party notice.

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

## Sources audited but not redistributed

The remaining sources are audited and recorded, but no case content from them is committed here.
Where a licence does not permit wholesale redistribution, the artifact ships case identifiers plus
a pinned fetch script and derived fields only, per SPEC.md section 16.

| Source | Licence verdict | Committed here |
| --- | --- | --- |
| AgentDojo | MIT, attribution | No (audit and fetch path only) |
| SafeClawBench | MIT, attribution | No (audit only) |
| Agentic prompt-injection 5K and boundary pairs | CC BY 4.0 declared but licence text not shipped | No (audit only) |
| ToolPrivacyBench | Unknown, no licence stated | No (audit only) |
| ASPI | No licence granted | No (fetch script only) |
| Contemporary Attacks | Not yet identified | No |

See `manifest/` for the pinned version, case counts before and after mapping, and drop reasons
for every source.
