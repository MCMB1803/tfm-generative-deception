"""Central configuration for the Generative Deception Framework.

Every tunable is read from the environment so the same image can be
redeployed with a different persona or model without a rebuild.
"""
import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# --- Inference engine -------------------------------------------------------
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama-llm:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:0.5b")

# Keeps the model resident in RAM between requests. Without this Ollama
# unloads after 5 minutes and the next command pays a multi-second reload,
# which is the single largest source of latency outliers.
MODEL_KEEP_ALIVE = os.getenv("MODEL_KEEP_ALIVE", "30m")

# Hard ceiling on generated tokens. Real recon command output is short;
# capping it is the cheapest latency control available.
MAX_TOKENS = _int("MAX_TOKENS", 64)
TEMPERATURE = _float("TEMPERATURE", 0.3)
LLM_TIMEOUT = _float("LLM_TIMEOUT", 20.0)

# --- Latency budget ---------------------------------------------------------
# TFM performance target: an attacker must not be able to fingerprint the
# decoy by response time. Anything above this is flagged in telemetry.
LATENCY_TARGET_MS = _float("LATENCY_TARGET_MS", 1000.0)

# --- Latency normalisation --------------------------------------------------
# Response time must depend on the command, never on the route that answered
# it. Without this the deterministic route (~2 ms) and the generative one
# (~2 s) form two separable populations and an attacker who times responses
# detects the decoy. See core/latency.py.
LATENCY_NORMALIZE = os.getenv("LATENCY_NORMALIZE", "true").lower() in ("1", "true", "yes")

# Median round-trip time attributed to a session, and its log-normal spread.
# Constant per session: an attacker connects over one network path.
LATENCY_RTT_MEDIAN_MS = _float("LATENCY_RTT_MEDIAN_MS", 700.0)
LATENCY_RTT_SIGMA = _float("LATENCY_RTT_SIGMA", 0.25)

# Ceiling on a drawn target, as a multiple of its class median. Stops a single
# outlier from being as conspicuous as the bimodality it replaced.
LATENCY_TAIL_CAP = _float("LATENCY_TAIL_CAP", 6.0)

# --- Generation budget ------------------------------------------------------
# Padding can only add time. When the model is still writing after its target
# has elapsed the sample stays distinguishable, and in the reference run that
# was the whole of the residual leak: `lsblk` and `vmstat 1 1` both saturated
# MAX_TOKENS=64 and overran their ~750 ms target by 500-2200 ms, which made the
# `proc_scan` class separable at AUC 1.00. The fix is to spend fewer tokens on
# the classes that cannot afford them, and a leaner prompt when even that is
# not enough. See core/latency.py::GenerationBudget.
GEN_BUDGET = os.getenv("GEN_BUDGET", "true").lower() in ("1", "true", "yes")

# Never generate fewer than this, whatever the arithmetic says: below roughly a
# line of output the answer stops being plausible and the content tell replaces
# the timing tell.
GEN_MIN_TOKENS = _int("GEN_MIN_TOKENS", 12)

# Fraction of the target the generative route may plan to consume. The rest
# absorbs the variance the estimate cannot predict.
GEN_SAFETY = _float("GEN_SAFETY", 0.75)

# Seed values for the two terms of the cost model, in ms. Both are re-estimated
# from the responses the model actually returns, so these only matter for the
# first few commands of a run; the defaults are the reference machine's
# measured figures (~12 ms/token generated, ~250 ms to evaluate a full prompt).
GEN_MS_PER_TOKEN = _float("GEN_MS_PER_TOKEN", 12.0)
GEN_PROMPT_OVERHEAD_MS = _float("GEN_PROMPT_OVERHEAD_MS", 250.0)

# Weight of a new observation in the running estimate of both terms.
GEN_EWMA_ALPHA = _float("GEN_EWMA_ALPHA", 0.3)

# Context replayed to the model, full and lean. The lean tier is used when the
# full one cannot fit the target: fewer turns and harder truncation cut prompt
# evaluation, which is the floor no token budget can get under. It costs
# session coherence, which is the trade the whole chapter is about.
GEN_CONTEXT_CHARS = _int("GEN_CONTEXT_CHARS", 600)
GEN_LEAN_CONTEXT_TURNS = _int("GEN_LEAN_CONTEXT_TURNS", 2)
GEN_LEAN_CONTEXT_CHARS = _int("GEN_LEAN_CONTEXT_CHARS", 160)

# --- Persona ----------------------------------------------------------------
PERSONA_PROFILE = os.getenv("PERSONA_PROFILE", "corporate-web-server")
PERSONA_CACHE = os.getenv("PERSONA_CACHE", "/app/data/persona.json")
PERSONA_SEED = _int("PERSONA_SEED", 1803)

# --- Telemetry --------------------------------------------------------------
# JSON Lines, one event per line: directly ingestable by Wazuh
# (<location> with a json decoder) or Filebeat -> Elasticsearch.
EVENT_LOG = os.getenv("EVENT_LOG", "/app/data/logs/deception-events.jsonl")
LATENCY_LOG = os.getenv("LATENCY_LOG", "/app/data/logs/latency.jsonl")

# --- Session ----------------------------------------------------------------
# Number of previous command/output pairs replayed to the LLM as context.
# Higher = more coherence, more prompt tokens, more latency.
SESSION_CONTEXT_TURNS = _int("SESSION_CONTEXT_TURNS", 6)
SESSION_IDLE_TIMEOUT = _float("SESSION_IDLE_TIMEOUT", 1800.0)

# --- Orchestrator API -------------------------------------------------------
AGENT_API_HOST = os.getenv("AGENT_API_HOST", "0.0.0.0")
AGENT_API_PORT = _int("AGENT_API_PORT", 8000)
