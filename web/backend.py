"""FastAPI/WebSocket backend for the EN2025 recorded-trace demo."""

from __future__ import annotations

import csv
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.detection.bag_of_apis import BagOfAPIsModel
from src.detection.neural_models import load_neural_artifact, select_device
from src.detection.replay import ReplaySession


ROOT = Path(os.environ.get("EN2025_ROOT", "EN2025"))
INVENTORY = Path(os.environ.get("EN2025_INVENTORY", "inventory.csv"))
MODEL_DIR = Path(os.environ.get("BAG_OF_APIS_MODEL", "models/bag_of_apis"))
NEURAL_MODEL_ROOT = Path(os.environ.get("NEURAL_MODEL_ROOT", "models"))
STATIC_DIR = Path(__file__).with_name("frontend").joinpath("dist")

app = FastAPI(title="EN2025 Streaming Detector")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_model: BagOfAPIsModel | None = None
_loaded_models: dict[str, Any] = {}
_samples: dict[str, dict[str, Any]] = {}
_sessions: dict[str, ReplaySession] = {}


def model() -> BagOfAPIsModel:
    global _model
    if _model is None:
        _model = BagOfAPIsModel.load(MODEL_DIR)
    return _model


def available_model(model_id: str) -> Any:
    if model_id == "bag_of_apis":
        return model()
    if model_id not in {"xran_style_cnn", "gru", "causal_transformer"}:
        raise ValueError(f"unknown model: {model_id}")
    if model_id not in _loaded_models:
        directory = NEURAL_MODEL_ROOT / model_id
        if not (directory / "model.pt").is_file() or not (directory / "metadata.json").is_file():
            raise ValueError(f"model artifact is not available: {model_id}")
        _loaded_models[model_id] = load_neural_artifact(directory, select_device("auto"))
    return _loaded_models[model_id]


def samples() -> dict[str, dict[str, Any]]:
    if _samples:
        return _samples
    with INVENTORY.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row.get("report_exists", "").lower() != "true":
                continue
            path = ROOT / row["relative_report_path"]
            if not path.is_file():
                continue
            sample_id = row["sample_hash"]
            _samples[sample_id] = {
                "sample_id": sample_id,
                "class_label": row["class_label"],
                "relative_report_path": row["relative_report_path"],
                "path": path,
            }
    return _samples


@app.get("/api/health")
def health() -> dict[str, Any]:
    loaded = model()
    return {"ok": True, "model_version": loaded.metadata.get("model_version"), "samples": len(samples())}


@app.get("/api/models")
def models() -> dict[str, Any]:
    loaded = model()
    result = [
            {
                "id": "bag_of_apis",
                "name": "Bag of APIs",
                "status": "ready",
                "vocabulary_size": len(loaded.vocabulary),
                "threshold": loaded.threshold,
                "metadata": loaded.metadata,
            },
            {
                "id": "xran_style_cnn",
                "name": "XRan-style CNN",
                "status": "ready" if (NEURAL_MODEL_ROOT / "xran_style_cnn" / "model.pt").is_file() else "not_implemented",
            },
            {
                "id": "gru",
                "name": "GRU",
                "status": "ready" if (NEURAL_MODEL_ROOT / "gru" / "model.pt").is_file() else "not_implemented",
            },
            {
                "id": "causal_transformer",
                "name": "Causal Transformer",
                "status": "ready"
                if (NEURAL_MODEL_ROOT / "causal_transformer" / "model.pt").is_file()
                else "not_implemented",
            },
        ]
    for item in result[1:]:
        if item["status"] == "ready":
            try:
                loaded = available_model(item["id"])
                item["threshold"] = loaded.threshold
                item["metadata"] = loaded.metadata
            except (RuntimeError, ValueError) as exc:
                item["status"] = "unavailable"
                item["error"] = str(exc)
    return {"models": result}


@app.get("/api/samples")
def sample_list() -> dict[str, Any]:
    result = []
    for sample in sorted(samples().values(), key=lambda item: (item["class_label"], item["sample_id"])):
        result.append({key: value for key, value in sample.items() if key != "path"})
    return {"samples": result}


def get_session(session_id: str, selected_model: str = "bag_of_apis") -> ReplaySession:
    if session_id not in _sessions or _sessions[session_id].model is not available_model(selected_model):
        _sessions[session_id] = ReplaySession(session_id, available_model(selected_model))
    return _sessions[session_id]


@app.websocket("/ws/replay/{session_id}")
async def replay_socket(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    session = get_session(session_id)
    await websocket.send_json({"type": "ready", "session_id": session_id, "model": model().metadata})
    try:
        while True:
            message = await websocket.receive_json()
            command = message.get("command")
            try:
                if command == "configure":
                    selected_model = str(message.get("model_id", "bag_of_apis"))
                    session = get_session(session_id, selected_model)
                    sample = samples().get(message.get("sample_id"))
                    if sample is None:
                        raise ValueError("sample not found")
                    await session.configure(sample, float(message.get("speed", 20)))
                    await websocket.send_json(
                        {
                            "type": "configured",
                            "sample": {key: value for key, value in sample.items() if key != "path"},
                            "total_events": session.total_events,
                            "threshold": session.model.threshold,
                            "model_id": selected_model,
                        }
                    )
                elif command == "start":
                    await session.start(websocket.send_json)
                elif command == "pause":
                    await session.pause()
                    await websocket.send_json({"type": "status", "status": "paused"})
                elif command == "resume":
                    await session.resume()
                    await websocket.send_json({"type": "status", "status": "running"})
                elif command == "reset":
                    await session.reset()
                    await websocket.send_json({"type": "status", "status": "idle"})
                elif command == "set_speed":
                    session.speed = max(0.0, min(float(message.get("speed", 20)), 100.0))
                else:
                    await websocket.send_json({"type": "error", "message": f"unknown command: {command}"})
            except Exception as exc:
                await websocket.send_json({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
    except WebSocketDisconnect:
        return


if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="frontend")
else:
    @app.get("/")
    def missing_frontend() -> FileResponse:
        raise RuntimeError("Frontend is not built. Run npm install && npm run build in web/frontend.")
