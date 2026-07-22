# Head-to-head benchmark runner (PowerShell) — reproduces the rows
# published in docs/BENCHMARKS_VS.md on your own machine.
#
# REQUIREMENTS
#   * Docker Desktop (with compose) — everything runs in containers; no
#     Rust toolchain needed on the host.
#   * The LoCoMo dataset file (user-supplied): github.com/snap-research/locomo
#   * ~5 minutes for the undercroft rows. Competitor rows additionally need
#     that system's local stack up (deploy/bench-vs/README.md) plus a local
#     LLM backend (LM Studio or Ollama) — and hours of wall-clock, because
#     extraction-based systems call an LLM on every write.
#
# PROCESS
#   1. Copy-Item benchmarks/vs.env.example benchmarks/vs.env   # then edit
#   2. pwsh benchmarks/run-vs.ps1                              # from anywhere
#   3. Read the summary; the full log lands in benchmarks/logs/local/
#      (gitignored — publish only reviewed logs, see benchmarks/logs/README.md)
#
# The script is a thin, honest wrapper around:
#   docker compose run --rm test cargo run --release -p undercroft-bench -- vs ...
# — the exact invocation the published rows used. Scoring, chunking, and
# corpus handling all live in the harness; nothing here can bias a number.

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $repo "benchmarks/vs.env"
if (-not (Test-Path $envFile)) {
    Write-Error "error: $envFile not found - Copy-Item benchmarks/vs.env.example benchmarks/vs.env and edit it"
}

# Parse the KEY=VALUE env file (comments and blanks ignored).
$cfg = @{}
foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*#' -or $line -match '^\s*$') { continue }
    $k, $v = $line -split '=', 2
    $cfg[$k.Trim()] = $v.Trim()
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Error "error: docker not found" }
docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Write-Error "error: docker compose plugin not found" }

$dataset = $cfg["LOCOMO_JSON"]
if (-not $dataset -or -not (Test-Path $dataset)) {
    Write-Error "error: LOCOMO_JSON does not point at a file (get it from github.com/snap-research/locomo)"
}

$system  = if ($cfg["SYSTEM"]) { $cfg["SYSTEM"] } else { "undercroft" }
$k       = if ($cfg["K"]) { $cfg["K"] } else { "10" }
$skip    = if ($cfg["SKIP"]) { $cfg["SKIP"] } else { "0" }
$qaLimit = if ($cfg["QA_LIMIT"]) { $cfg["QA_LIMIT"] } else { "0" }

$benchArgs = @("vs", "/data/$(Split-Path -Leaf $dataset)", "--system", $system, "-k", $k, "--skip", $skip, "--qa-limit", $qaLimit)
if ($cfg["LIMIT"]) { $benchArgs += @("--limit", $cfg["LIMIT"]) }

$runEnv = @()
$features = @()
if ($system -eq "undercroft" -and $cfg["ONNX_MODEL"]) {
    if (-not (Test-Path $cfg["ONNX_MODEL"]) -or -not ($cfg["ONNX_TOKENIZER"] -and (Test-Path $cfg["ONNX_TOKENIZER"]))) {
        Write-Error "error: ONNX_MODEL/ONNX_TOKENIZER set but files missing"
    }
    $features = @("--features", "onnx")
    $runEnv += @("-e", "UNDERCROFT_EMBEDDER=onnx",
                 "-e", "UNDERCROFT_ONNX_MODEL=/models/$(Split-Path -Leaf $cfg['ONNX_MODEL'])",
                 "-e", "UNDERCROFT_ONNX_TOKENIZER=/models/$(Split-Path -Leaf $cfg['ONNX_TOKENIZER'])")
}
if ($system -ne "undercroft") {
    $vsUrl = if ($cfg["VS_URL"]) { $cfg["VS_URL"] } else { "http://host.docker.internal:8765" }
    $runEnv += @("-e", "UNDERCROFT_VS_URL=$vsUrl")
    Write-Host "note: '$system' must already be up and configured - see deploy/bench-vs/README.md"
}

$logDir = Join-Path $repo "benchmarks/logs/local"
New-Item -ItemType Directory -Force $logDir | Out-Null
$log = Join-Path $logDir "$system-$(Get-Date -Format yyyyMMdd-HHmmss).log"

$mounts = @("-v", "$(Split-Path -Parent $dataset):/data:ro")
if ($features.Count -gt 0) { $mounts += @("-v", "$(Split-Path -Parent $cfg['ONNX_MODEL']):/models:ro") }

Push-Location $repo
try {
    Write-Host "== building the bench image (first run takes a few minutes) =="
    docker compose build test
    if ($LASTEXITCODE -ne 0) { Write-Error "bench image build failed" }
    Write-Host "== running: system=$system k=$k skip=$skip limit=$(if ($cfg['LIMIT']) { $cfg['LIMIT'] } else { 'all' }) qa_limit=$qaLimit =="
    docker compose run --rm @mounts @runEnv test cargo run --release @features -p undercroft-bench -- @benchArgs 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) { Write-Error "benchmark run failed - see $log" }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "== done - full log: $log =="
Select-String -Path $log -Pattern "^VS_(RAW|TIMING)|^VS — " | ForEach-Object { $_.Line }
