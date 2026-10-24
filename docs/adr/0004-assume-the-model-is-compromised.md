# 0004 Defences against prompt injection assume the model has been fooled

Status: accepted, 2026-10-22

A companion model reads text other people wrote: character cards, stored memories, web pages,
other users' board posts. Prompt-level defences lower the odds that it obeys an injection; nothing
makes that impossible. So the platform's defences are designed and tested against a model that
**always** obeys (`aisec/companion.py: CompromisedModel`), and the harness judges outcomes from what
a permissive chat client would load and show and what tools actually ran, never from the defences'
own verdicts.

Layers, each measured on its own (ablation in `ceg aisec`):

1. Render policy: escape raw HTML, images only from the platform's media hosts, links to other
   hosts made inert. Closes zero-click exfiltration (the channel GitHub Copilot Chat and others
   fixed by restricting image hosts).
2. Leak guard: a canary in the system prompt and shingle overlap, also on decoded and spaced or
   reversed text.
3. Tool broker: calls bound to the session's user; sharing and contact changes held for the user's
   confirmation; outbound fetches to an allowlist; outbound arguments refused when they carry the
   user's private data, including encoded forms.

The judge (`aisec/judge.py`) shares no code with the defences, so an encoding a defence misses
is not also invisible to the evaluation ([postmortem](../postmortems/2026-10-24-judge-shared-the-guards-detector.md)).

One assumption is stated rather than enforced: closed code blocks and inline code are passed through
unchanged, because CommonMark renderers show them as text. A client that rendered HTML inside code
blocks would need the policy to escape them again.

The model is simulated, which makes the evaluation reproducible and free and says nothing about how
often a real model obeys. That is a different question, measured elsewhere.
