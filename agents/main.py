"""HTTP entry point for the deception-agent service.

The decoy protocol frontends call this API. Keeping the orchestrator behind
HTTP rather than importing it into the SSH server is deliberate: a second
decoy (HTTP, FTP, RDP -- the future work in section 5.3) attaches by speaking
this API, and the persona, artefacts and session model are shared rather than
reimplemented per protocol.

This API is bound to the internal `deception-net` bridge only. It is never
published to the host and must never be exposed to the attacker's network.
"""
from __future__ import annotations

import logging
import threading

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from core import config
from core.telemetry import configure_logging
from orchestrator import DeceptionOrchestrator

configure_logging()
log = logging.getLogger("api")

app = FastAPI(
    title="Generative Deception Framework - Agent API",
    description="Orquestador multi-agente del marco de ciberengano generativo (TFM UCM)",
    version="1.0.0",
)

orchestrator = DeceptionOrchestrator()


@app.on_event("startup")
def _startup() -> None:
    # Bootstrap in the background: Ollama may still be pulling the model, and
    # the API must answer /health meanwhile so compose healthchecks succeed.
    threading.Thread(target=orchestrator.bootstrap, daemon=True,
                     name="bootstrap").start()


# -- schemas -----------------------------------------------------------------
class OpenSessionRequest(BaseModel):
    src_ip: str = Field(..., description="IP de origen del atacante")
    src_port: int = Field(0, description="Puerto de origen")


class AuthRequest(BaseModel):
    session_id: str
    username: str
    password: str = ""
    method: str = "password"


class CommandRequest(BaseModel):
    session_id: str
    command: str


class CloseRequest(BaseModel):
    session_id: str
    reason: str = "client_disconnect"


# -- routes ------------------------------------------------------------------
@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok" if orchestrator.ready else "starting",
            "ready": orchestrator.ready}


@app.get("/stats")
def stats() -> dict[str, object]:
    return orchestrator.stats()


@app.get("/persona")
def persona() -> dict[str, object]:
    if not orchestrator.ready or orchestrator.persona is None:
        raise HTTPException(503, "El orquestador aun no esta listo")
    return orchestrator.persona.to_dict()


@app.post("/session/open")
def open_session(req: OpenSessionRequest) -> dict[str, object]:
    if not orchestrator.ready:
        raise HTTPException(503, "El orquestador aun no esta listo")
    session = orchestrator.open_session(req.src_ip, req.src_port)
    return {
        "session_id": session.session_id,
        "banner": orchestrator.banner(session.session_id),
        "prompt": orchestrator.prompt(session.session_id),
    }


@app.post("/session/auth")
def authenticate(req: AuthRequest) -> dict[str, object]:
    if not orchestrator.authenticate(req.session_id, req.username, req.password, req.method):
        raise HTTPException(404, "Sesion desconocida")
    # Always accepted: the decoy exists to observe post-authentication behaviour.
    return {"accepted": True}


@app.post("/session/command")
def execute(req: CommandRequest) -> dict[str, object]:
    try:
        return orchestrator.execute(req.session_id, req.command)
    except KeyError:
        raise HTTPException(404, "Sesion desconocida")
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


@app.post("/session/close")
def close_session(req: CloseRequest) -> dict[str, object]:
    summary = orchestrator.close_session(req.session_id, req.reason)
    if summary is None:
        raise HTTPException(404, "Sesion desconocida")
    return summary


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.AGENT_API_HOST, port=config.AGENT_API_PORT,
                log_level="info")
