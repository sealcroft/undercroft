# Architecture & process diagrams

Standalone SVG renders of every diagram in the documentation, for use in
slides, issues, or anywhere the Mermaid source can't render. The **Mermaid
sources in the docs are canonical** — these files are regenerated from
them (`src/*.mmd` holds the extracted sources; rendered with the pinned
`minlag/mermaid-cli:10.9.1` image, light theme, white background):

```bash
docker run --rm -v "$PWD/docs/diagrams:/data" --entrypoint sh minlag/mermaid-cli:10.9.1 \
  -c 'for f in /data/src/*.mmd; do n=$(basename "$f" .mmd); \
      /home/mermaidcli/node_modules/.bin/mmdc -p /puppeteer-config.json \
      -i "$f" -o "/data/$n.svg" -b white -t default -q; done'
```

| Diagram | Lives in |
|---|---|
| [architecture-components](architecture-components.svg) — 11-crate dependency graph, orchestrator's HTTP-only boundary | [architecture.md](../architecture.md) |
| [architecture-key-hierarchy](architecture-key-hierarchy.svg) — master key → HKDF per vault → AAD domains | [architecture.md](../architecture.md) |
| [architecture-write-path](architecture-write-path.svg) — seal → HMAC → single-tx chain advance → manifest anchor | [architecture.md](../architecture.md) |
| [architecture-search-pipeline](architecture-search-pipeline.svg) — candidates → verify → fusion → rescore | [architecture.md](../architecture.md) |
| [retrieval-tier-map](retrieval-tier-map.svg) — candidate tiers × rescore tiers | [RETRIEVAL_SCALING.md](../RETRIEVAL_SCALING.md) |
| [security-seal-verify](security-seal-verify.svg) — one record at rest and on read | [security.md](../security.md) |
| [security-chain-reconciliation](security-chain-reconciliation.svg) — open-time crash vs rollback states | [security.md](../security.md) |
| [security-auth-layers](security-auth-layers.svg) — bearer + per-vault assertion decision flow | [security.md](../security.md) |
| [multitenancy-topology](multitenancy-topology.svg) — tenants → orchestrator → engines → vaults | [MULTI_TENANCY.md](../MULTI_TENANCY.md) |
| [multitenancy-data-plane](multitenancy-data-plane.svg) — routed request, auth swapped at the boundary | [MULTI_TENANCY.md](../MULTI_TENANCY.md) |
| [multitenancy-migration](multitenancy-migration.svg) — count-verified migration incl. failure branch | [MULTI_TENANCY.md](../MULTI_TENANCY.md) |
| [integrations-surfaces](integrations-surfaces.svg) — clients, surfaces, ingestion, accelerators | [integrations.md](../integrations.md) |
| [observability-pipeline](observability-pipeline.svg) — opt-in telemetry pipeline, gate per edge | [observability page](../../website/src/observability.md) |
| [runbook-tamper-response](runbook-tamper-response.svg) — tamper triage process | [runbook page](../../website/src/runbook.md) |
