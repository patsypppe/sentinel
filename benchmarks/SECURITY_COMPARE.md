# Tool-description poisoning: Sentinel vs Cisco mcp-scanner (offline YARA)

15 poisoned tools, 6 hard negatives, 362 real tools from published servers (taken as benign, then the flagged ones read by hand).

| Tool | Poisoned caught: explicit | hidden characters | evasive | all | Hard negatives wrongly flagged | Real tools flagged |
|---|---|---|---|---|---|---|
| Sentinel (all categories) | 5/8 | 3/3 | 0/4 | 8/15 | 2/6 | 4/362 |
| Sentinel (without credential-path mentions) | 4/8 | 3/3 | 0/4 | 7/15 | 0/6 | 0/362 |
| Cisco mcp-scanner (YARA, offline) | 1/8 | 0/3 | 1/4 | 2/15 | 3/6 | 16/362 |

Missed by each (poisoned):

- Sentinel (all categories): cross-tool-shadowing, evasive-base64, evasive-french, evasive-paraphrase, evasive-split, exfil-url, role-injection
- Sentinel (without credential-path mentions): cross-tool-shadowing, evasive-base64, evasive-french, evasive-paraphrase, evasive-split, exfil-url, param-description-injection, role-injection
- Cisco mcp-scanner (YARA, offline): conceal-shell, cross-tool-shadowing, evasive-base64, evasive-french, evasive-paraphrase, exfil-url, html-comment, ignore-previous, param-description-injection, role-injection, system-prompt-leak, unicode-tag-smuggling, zero-width
