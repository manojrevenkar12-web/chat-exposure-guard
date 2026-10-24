# 0002 An issue is fixed when every tool that reported it stops, in a full scan

Status: accepted, 2026-10-20

An issue records which tools report it. A full scan of a scope (the repository or one service) by
tool X that no longer reports the issue removes X from that list; the issue is fixed when the list
is empty. A partial scan (a pull-request scan, a single directory) never fixes anything, because
"not reported" there means "not looked at".

If a fixed issue is reported again it **reopens**, keeping its id and history, with a new opening
time for the due date. A revert of a fix is a regression of a known weakness, not a new one.

Suppressions are explicit and dated: a false positive with a reason, or a risk acceptance with an
expiry of at most 90 days (`config/settings.yaml`). An expired acceptance puts the issue back in
the queue.
