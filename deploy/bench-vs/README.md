# bench-vs — competitor stacks for the head-to-head harness

Local, fully documented deployments of the systems compared in
[docs/BENCHMARKS_VS.md](../../docs/BENCHMARKS_VS.md). Nothing here is
part of the undercroft battery — these compose files exist so a
published benchmark row is reproducible, image-pinned, and cloud-free.

## Shared local model backend

Extraction-based systems need an LLM and an embedder on every write.
All competitor rows in one published run use the **same** local
OpenAI-compatible backend so no system pays a different model tax. Two
supported shapes:

- **LM Studio on the host** (preferred when available — GPU-accelerated,
  so competitor ingest isn't throttled by our benchmark rig): serve at
  the default `http://localhost:1234/v1`; containers reach it as
  `http://host.docker.internal:1234/v1`. Load one chat model (e.g. a
  qwen3.5-9b-class instruct) and one embedding model (e.g.
  `text-embedding-nomic-embed-text-v1.5`).
- **Ollama in Docker** (fully containerized alternative):

  ```bash
  docker compose -f docker-compose.yml up -d ollama
  docker compose -f docker-compose.yml exec ollama ollama pull llama3.2:3b
  docker compose -f docker-compose.yml exec ollama ollama pull nomic-embed-text
  ```

Either way, the exact backend + model tags used for a published row are
recorded in that row's notes column. Note the deliberate asymmetry:
competitors get the *fastest* local backend available while the
undercroft rows use no LLM at all — generosity runs toward them.

## mem0 (OSS server)

mem0's self-hosted REST server, configured for Ollama (no cloud keys).
Follow mem0's current self-hosting docs for the server image/compose —
their stack (server + vector store) evolves quickly, so we pin by image
digest *at run time* and record the digest in the results row. Once up,
point the harness at it:

```bash
docker compose run --rm test \
  cargo run --release -p undercroft-bench -- vs \
  /data/locomo10.json --system mem0 --url http://host.docker.internal:8000
```

Endpoint defaults are mem0's documented `POST /v1/memories/` and
`POST /v1/memories/search/`; override with `UNDERCROFT_VS_ADD_PATH` /
`UNDERCROFT_VS_SEARCH_PATH` if the deployed version differs.

## Supermemory (self-hosted)

Supermemory publishes a self-hosting path ("one binary"). Run it per
their docs with local storage, record the version, then:

```bash
docker compose run --rm test \
  cargo run --release -p undercroft-bench -- vs \
  /data/locomo10.json --system supermemory --url http://host.docker.internal:8080
```

Defaults target `POST /v3/memories` / `POST /v3/search`
(`UNDERCROFT_VS_*` overrides available, including `UNDERCROFT_VS_BEARER`
if the instance enforces auth).

## Rules of engagement

- Local-vs-local only: no competitor row runs against a paid cloud API.
- Best documented local configuration, image/version recorded per row.
- Adapters are pass-throughs; if an adapter mis-drives a system, fix it
  by PR and the affected rows are re-run.
