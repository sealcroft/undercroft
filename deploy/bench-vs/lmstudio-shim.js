// Transport shim between mem0/OpenMemory and LM Studio (bench-vs only).
//
// mem0's extraction client sends the older OpenAI dialect
// `response_format: {"type": "json_object"}`; LM Studio's server accepts
// only `json_schema` or `text` and 400s the call. This proxy forwards
// every request to the host's LM Studio verbatim EXCEPT that it drops a
// `json_object` response_format (mem0's prompts already instruct JSON,
// and qwen3.6 emits it reliably — verified in the run log). It never
// touches message content, model choice, or responses — a pure dialect
// translation, documented in docs/BENCHMARKS_VS.md row notes.
//
// Listens on :1234 inside the network namespace it shares with the
// OpenMemory container (whose mem0 lmstudio provider is hardwired to
// localhost:1234); upstream is the host's real LM Studio.
const http = require("http");

const UPSTREAM_HOST = process.env.UPSTREAM_HOST || "host.docker.internal";
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 1234);

http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      let body = Buffer.concat(chunks);
      if ((req.headers["content-type"] || "").includes("application/json")) {
        try {
          const parsed = JSON.parse(body.toString("utf8"));
          if (
            parsed &&
            parsed.response_format &&
            parsed.response_format.type === "json_object"
          ) {
            delete parsed.response_format;
            body = Buffer.from(JSON.stringify(parsed), "utf8");
          }
        } catch (_) {
          /* non-JSON body: forward verbatim */
        }
      }
      const headers = { ...req.headers };
      delete headers["content-length"];
      delete headers.host;
      headers["content-length"] = Buffer.byteLength(body);
      // OpenMemory hardcodes its qdrant collection at 1536 dims (not
      // configurable via its API); nomic embeds at 768. Zero-padding
      // changes no dot product and no vector norm, so cosine rankings
      // are mathematically identical — a lossless dimension adaptation,
      // applied only when PAD_EMBED_TO is set.
      const padTo = Number(process.env.PAD_EMBED_TO || 0);
      const isEmbeddings = padTo > 0 && req.url.includes("/embeddings");
      const debugChat = !!process.env.SHIM_DEBUG && req.url.includes("/chat/");
      if (debugChat) {
        console.log("CHAT_REQ", body.toString("utf8").slice(0, 900));
      }
      const up = http.request(
        {
          host: UPSTREAM_HOST,
          port: UPSTREAM_PORT,
          method: req.method,
          path: req.url,
          headers,
        },
        (upRes) => {
          if ((!isEmbeddings && !debugChat) || upRes.statusCode !== 200) {
            res.writeHead(upRes.statusCode, upRes.headers);
            upRes.pipe(res);
            return;
          }
          const parts = [];
          upRes.on("data", (c) => parts.push(c));
          upRes.on("end", () => {
            if (debugChat) {
              console.log(
                "CHAT_RESP",
                Buffer.concat(parts).toString("utf8").slice(0, 600)
              );
            }
            let out = Buffer.concat(parts);
            try {
              const j = JSON.parse(out.toString("utf8"));
              for (const item of j.data || []) {
                const e = item.embedding;
                if (Array.isArray(e) && e.length < padTo) {
                  item.embedding = e.concat(new Array(padTo - e.length).fill(0));
                }
              }
              out = Buffer.from(JSON.stringify(j), "utf8");
            } catch (_) {
              /* forward verbatim */
            }
            const h = { ...upRes.headers };
            delete h["content-length"];
            delete h["transfer-encoding"];
            h["content-length"] = Buffer.byteLength(out);
            res.writeHead(upRes.statusCode, h);
            res.end(out);
          });
        }
      );
      up.on("error", (e) => {
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
        }
        res.end(JSON.stringify({ error: `shim upstream: ${e.message}` }));
      });
      // A silently hung upstream call must fail fast, not wedge the single
      // server worker behind it for the client's whole read timeout: abort
      // after 5 minutes (far above any healthy local-LLM call) so the
      // caller gets a 502 it can retry.
      up.setTimeout(300000, () => up.destroy(new Error("upstream timeout (300s)")));
      up.end(body);
    });
  })
  .listen(1234, "0.0.0.0", () => {
    console.log(`lmstudio-shim on :1234 -> ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  });
