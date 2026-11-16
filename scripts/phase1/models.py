"""Typed, JSON-serializable records used by the Phase 1 pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    sample_id: str
    class_label: str
    report_path: str
    source_process_index: int
    process_call_position: int
    process_id: str
    parent_process_id: Optional[str]
    process_name: Any
    module_path: Any
    call_id_raw: Any
    timestamp_raw: Any
    api_raw: Any
    api_normalized: str
    category_raw: Any
    thread_id_raw: Any
    status_raw: Any
    return_raw: Any
    repeated_raw: Any
    arguments_raw: Any
    arguments_normalized: Dict[str, List[Dict[str, Any]]]
    operation_kind: str
    handle_observations: List[Dict[str, Any]] = field(default_factory=list)
    path_observations: List[Dict[str, Any]] = field(default_factory=list)
    file_identity_candidates: List[Dict[str, Any]] = field(default_factory=list)
    evidence_state: str = "observed"
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "class_label": self.class_label,
            "report_path": self.report_path,
            "source_process_index": self.source_process_index,
            "process_call_position": self.process_call_position,
            "process_id": self.process_id,
            "parent_process_id": self.parent_process_id,
            "process_name": self.process_name,
            "module_path": self.module_path,
            "call_id_raw": self.call_id_raw,
            "timestamp_raw": self.timestamp_raw,
            "api_raw": self.api_raw,
            "api_normalized": self.api_normalized,
            "category_raw": self.category_raw,
            "thread_id_raw": self.thread_id_raw,
            "status_raw": self.status_raw,
            "return_raw": self.return_raw,
            "repeated_raw": self.repeated_raw,
            "arguments_raw": self.arguments_raw,
            "arguments_normalized": self.arguments_normalized,
            "operation_kind": self.operation_kind,
            "handle_observations": self.handle_observations,
            "path_observations": self.path_observations,
            "file_identity_candidates": self.file_identity_candidates,
            "evidence_state": self.evidence_state,
            "warnings": self.warnings,
        }

