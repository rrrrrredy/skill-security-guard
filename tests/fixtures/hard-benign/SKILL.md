---
name: checkout-health
description: Summarize the local checkout and report whitespace problems before a release.
---

Run the helpers from the checkout root. The Python helper reports the worktree state and
encodes the public Git revision for a build receipt. The shell helper checks whitespace
and lists tracked agent configuration and the configured hooks path for release review.
