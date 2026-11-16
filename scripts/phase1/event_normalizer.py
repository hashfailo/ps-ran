"""Lossless event-derived labels and descriptive argument observations."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .cape_parser import event_arguments
from .models import Event

PATH_NAMES = {
    "filename", "file_name", "handle_name", "existingfilename",
    "newfilename", "filepath", "path", "pathname",
}
HANDLE_NAMES = {"filehandle", "handle", "handlevalue", "fileobject"}
PATH_RE = re.compile(r"(path|filename|file_name|handle_name|pathname)$", re.I)
HANDLE_RE = re.compile(r"(handle|fileobject|file_object)", re.I)

# Only these API/argument pairs are eligible for file identity tracking.
# Other handle-like arguments remain raw observations with object_type
# ``non_file_or_unknown``.
FILE_HANDLE_ROLES = {
    "ntcreatefile": {"filehandle": "create_attempt"},
    "ntopenfile": {"filehandle": "open_attempt"},
    "ntwritefile": {"filehandle": "operation"},
    "writefile": {"filehandle": "operation"},
    "ntreadfile": {"filehandle": "operation"},
    "readfile": {"filehandle": "operation"},
    "ntsetinformationfile": {"filehandle": "operation"},
    "ntqueryinformationfile": {"filehandle": "operation"},
    "ntflushbuffersfile": {"filehandle": "operation"},
    "ntqueryeafile": {"filehandle": "operation"},
    "ntseteafile": {"filehandle": "operation"},
    "ntclose": {"handle": "close"},
}

UNCERTAIN_HANDLE_APIS = {
    "ntduplicateobject",
    "ntdeviceiocontrolfile",
    "ntqueryobject",
}


def unwrap(value: Any) -> Any:
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def state(value: Any) -> str:
    value = unwrap(value)
    if value is None:
        return "null"
    if isinstance(value, str):
        return "empty" if not value.strip() else "usable"
    if isinstance(value, (bool, int, float)):
        return "usable"
    return "unusable"


def is_path_name(name: str) -> bool:
    return name.lower() in PATH_NAMES or bool(PATH_RE.search(name))


def is_handle_name(name: str) -> bool:
    return name.lower() in HANDLE_NAMES or bool(HANDLE_RE.search(name))


def file_handle_role(api: str, name: str) -> str | None:
    return FILE_HANDLE_ROLES.get(api, {}).get(name.lower())


def path_representation(value: Any) -> str:
    if state(value) != "usable":
        return state(value)
    text = str(unwrap(value))
    lower = text.lower()
    if lower.startswith("\\\\"):
        return "unc_network"
    if lower.startswith("\\device\\"):
        return "nt_device"
    if lower.startswith(("\\??\\", "\\?\\")):
        return "dos_device"
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return "drive_letter"
    if lower.startswith(("hklm\\", "hkcu\\", "hkcr\\", "hkey_")):
        return "registry_or_configuration"
    if text.endswith(("\\", "/")):
        return "directory_like"
    return "relative_or_unknown"


def operation_kind(api: str) -> str:
    exact = {
        "ntcreatefile": "create_or_open",
        "ntopenfile": "open",
        "ntwritefile": "write",
        "writefile": "write",
        "ntsetinformationfile": "set_file_information",
        "ntclose": "close",
        "deletefilew": "delete",
        "deletefilea": "delete",
        "ntdeletefile": "delete",
        "movefilew": "rename",
        "movefileexw": "rename",
        "copyfilew": "copy",
        "copyfilea": "copy",
    }
    return exact.get(api, "unknown")


def enrich_event(event: Event) -> Event:
    args = event_arguments(event)
    event.operation_kind = operation_kind(event.api_normalized)
    for name, values in event.arguments_normalized.items():
        for entry in values:
            value = entry.get("value")
            if is_path_name(name):
                event.path_observations.append(
                    {
                        "argument_name": name,
                        "raw_value": value,
                        "state": state(value),
                        "representation": path_representation(value),
                    }
                )
            if is_handle_name(name):
                raw = unwrap(value)
                normalized = None if state(value) != "usable" else str(raw).strip().lower()
                role = file_handle_role(event.api_normalized, name)
                event.handle_observations.append(
                    {
                        "argument_name": name,
                        "raw_value": value,
                        "normalized_handle": normalized,
                        "state": state(value),
                        "object_type": "file_candidate" if role else (
                            "non_file_or_unknown"
                            if event.api_normalized not in UNCERTAIN_HANDLE_APIS
                            else "uncertain"
                        ),
                        "file_handle_role": role,
                    }
                )
    return event
