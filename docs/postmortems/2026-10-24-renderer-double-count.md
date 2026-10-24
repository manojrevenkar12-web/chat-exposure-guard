# The test client counted every allowed image as a link too

Date: 2026-10-24. Found by: `tests/test_aisec.py::test_render_policy_closes_zero_click_channels`.
Impact: the published ablation numbers were not affected (the judge only counts links that carry
private data to untrusted hosts), but the client model was wrong.

## What happened

The permissive client (`aisec/client.py`) finds what a chat client would load (images, CSS,
prefetch) and what it would make clickable. Its bare-URL linkifier ran over the whole reply,
including the inside of Markdown image syntax and HTML attributes, so `![x](https://media...)`
was both a fetch and a link. Real renderers do not linkify inside image or link syntax.

## Fix

Bare URLs are linkified only in text outside Markdown images, links, reference definitions and HTML
tags. A test asserts the exact fetch and link lists after the render policy.

## What we keep from it

The harness is the thing that decides whether a defence works, so its client deserves the same
tests as the defences. The ablation table was re-run after the fix and did not change.
