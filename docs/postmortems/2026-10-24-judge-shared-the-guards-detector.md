# The prompt-injection judge could not see what the defences missed

Date: 2026-10-24. Found by: the first held-out attack set (`heldout/aisec-v1`), written by someone
who had seen neither the defences nor the development corpus. Impact: the development ablation said
"0 of 38 attacks succeed with every defence on", and that number could not have been anything else
for a whole class of attacks.

## What happened

The harness judged "did the system prompt leak" with the same `LeakGuard` the pipeline uses as a
defence, and "did private data leave" with the same `PrivateData` matcher the tool broker uses. A
leak in an encoding the guard does not know was therefore invisible to both: the defence let it
through and the judge agreed nothing had happened. The test client also imported the render
policy's Markdown regexes, so a Markdown syntax the policy misses would have been missed by the
client as well.

The held-out set showed it directly: eight of its 46 attacks "failed" even with **no defences**,
including a marker spelled backwards, a base64 run after `?d=`, and sharing the whole conversation
with an outside address (no private text in the arguments, so the old judge saw no exfiltration).

## Fix

* `aisec/judge.py`: the judge's own detector, sharing no code with the defences. It looks for each
  value in every URL, HTML, base64, base64url and hex decoding of the text, each also reversed and
  with spacing removed, and parses hosts itself.
* The test client has its own Markdown patterns.
* Exfiltration goals count the system prompt and its marker as well as the user's data, and
  `share_conversation` to anyone outside the platform is exfiltration in itself.
* Then the defences were fixed where the corrected judge showed gaps: the leak guard reads text
  backwards and with punctuation removed; outbound tool arguments that carry the system prompt are
  refused; code blocks are shown as written (the render policy had broken a curl example and an
  image URL with `&` in it).

`heldout/aisec-v1` and `aisec-v2` became regression sets after their failures were studied.
`aisec-v3` was written afterwards by a third writer and run once.

## What we keep from it

A judge that reuses the system's own checks grades the system against itself. The rule is now in
`CLAUDE.md`, and `tests/test_aisec.py::test_the_judge_does_not_share_the_guards_blind_spots`
checks the judge on forms the guard was blind to.
