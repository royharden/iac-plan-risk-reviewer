# Architecture

The product accepts one bounded saved JSON file. Ingress retains a raw-byte digest and ordered resource changes, distinguishes missing/null/unknown/sensitive values, and rejects malformed structures. Rule evaluation emits one of introduced risk, unchanged risk, clear or indeterminate, independently of any model. Coverage records remain separate from those outcomes.

Evidence uses RFC6901 locations in that pinned local document and checks masks and identity. Decision evidence must resolve before a determinate finding can ship; missing optional evidence removes that fact and adds a limitation. The source is reopened only locally, with digest checks; it is never executed, fetched or embedded wholesale.

Private reports preserve exact addresses and pointers as an explicitly sensitive local artifact. Shareable reports and model capsules contain random IDs and whitelisted typed facts, excluding addresses, pointers, filenames, tags, arbitrary strings and private mappings. HTML escapes all text and loads no external assets.

The default CLI is read/export only. No Terraform, cloud SDK, subprocess, network, database or server is part of the review pipeline. A future optional provider transport has a separate approval boundary and all-attempt budget journal; finite selectors cannot mutate rule outcomes. Free prose and model-only prediction remain isolated experimental arms.

Evaluation sources import independently authored gold and measured rows. A fresh hidden corpus must be independently sealed and lineage-disjoint before tuning; it is consumed after exposure. Detector authors have supplied no hidden oracle here. Static construction acceptance does not close release acceptance.
