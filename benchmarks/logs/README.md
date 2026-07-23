# Benchmark logs — raw, as measured

Every number published in [docs/BENCHMARKS_VS.md](../../docs/BENCHMARKS_VS.md),
[docs/RETRIEVAL_SCALING.md](../../docs/RETRIEVAL_SCALING.md), and the
landing page traces to a raw log in this directory, captured from the
run that produced it. Logs are committed verbatim except for one
standing rule:

**No sensitive data.** Logs contain progress lines, scores, timings,
and configuration echoes only — never benchmark-corpus content, never
credentials, never machine-identifying material beyond what the
methodology pages already state. Each file is reviewed against that
rule before it lands here; if you spot a violation, open an issue and
it will be scrubbed with the history noted.

| Log | What it is |
|---|---|
| `vs_native_locomo.log` | head-to-head native row, LoCoMo full corpus (R@10 94.6%) |
| `vs_native_locomo_subset.log` | native row on the mem0-comparison subset (96.7%) |
| `vs_native_onnx_subset.log` | MiniLM ONNX row on the same subset (97.4%) |
| `vs_mem0_locomo.log` | mem0/OpenMemory measured row, convos 1–2 shard (67.9%) |
| `vs_mem0_convo3.log` | mem0 convo-3 shard (112/193, 58.0%; run ended at the convo-4 boundary — see BENCHMARKS_VS notes) |
| `vs_mem0_convo4.log` | mem0 convo-4 shard (166/260, 63.8%; run ended at the convo-5 boundary) |
| `vs_mem0_locomo_5_10.log` | mem0 convos 5–10 shard (843/1227, 68.7%) — completes the full-corpus row (1326/1982, 66.9%) |
| `colbert_fde_locomo2.log` | best-local config, LoCoMo full corpus (96.5%, v0.23.0) |
| `pqpage_spike.log` | sealed page-tier research spike, 10⁶–10⁷ synthetic |
| `fde_slab_sweep.log`, `fde_slab_sweep2.log` | inverted-FDE containment/latency sweeps (v0.39.0 gate) |
| `fde_pq_sweep.log` | bounded-RAM FDE tier sweeps (v0.24.0) |

Head-to-head shard logs (e.g., additional LoCoMo conversations for a
competitor row) are appended here as their runs complete; `VS_RAW`
lines are shard-additive by design, so published totals are
recomputable from the files alone.
