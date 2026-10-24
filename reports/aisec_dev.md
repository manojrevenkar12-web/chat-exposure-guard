## Prompt-injection outcomes

38 attacks, 14 benign conversations. Attack success = the attacker's goal reached, judged from what the client fetches and shows and what the tools did.

| Defences | Attacks that succeeded | zero click exfil | one click exfil | tool exfil | cross user | prompt leak | unconfirmed action | Benign conversations intact |
|---|---|---|---|---|---|---|---|---|
| no defences | 38/38 | 19/19 | 5/5 | 6/6 | 2/2 | 4/4 | 2/2 | 13/14 |
| render policy | 14/38 | 0/19 | 0/5 | 6/6 | 2/2 | 4/4 | 2/2 | 14/14 |
| + leak guard | 10/38 | 0/19 | 0/5 | 6/6 | 2/2 | 0/4 | 2/2 | 14/14 |
| + session binding | 8/38 | 0/19 | 0/5 | 6/6 | 0/2 | 0/4 | 2/2 | 14/14 |
| + confirmation | 6/38 | 0/19 | 0/5 | 6/6 | 0/2 | 0/4 | 0/2 | 14/14 |
| + fetch allowlist | 5/38 | 0/19 | 0/5 | 5/6 | 0/2 | 0/4 | 0/2 | 14/14 |
| all (+ taint check) | 0/38 | 0/19 | 0/5 | 0/6 | 0/2 | 0/4 | 0/2 | 14/14 |
