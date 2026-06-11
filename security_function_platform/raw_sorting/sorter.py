from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Callable

RAW_SORTING_DIR = Path("config_files/raw_sorting")
RAW_SORTING_INDEX = RAW_SORTING_DIR / "raw_sorting_index.json"
MODULES_DIR = Path("modules")


def load_raw_sorting_index() -> dict[str, Any]:
    sorters: list[dict[str, Any]] = []
    fallback = "raw"

    for index_path in _raw_sorting_index_paths():
        loaded = _load_raw_sorting_index_file(index_path)
        if loaded["fallback"] != "raw" and fallback == "raw":
            fallback = loaded["fallback"]
        sorters.extend(loaded["sorters"])

    return {"sorters": sorters, "fallback": fallback}


def _raw_sorting_index_paths() -> list[Path]:
    paths: list[Path] = []
    if RAW_SORTING_INDEX.is_file():
        paths.append(RAW_SORTING_INDEX)
    if MODULES_DIR.is_dir():
        for path in sorted(MODULES_DIR.glob("*/config_files/raw_sorting/raw_sorting_index.json")):
            if path.resolve() != RAW_SORTING_INDEX.resolve():
                paths.append(path)
    return paths


def _load_raw_sorting_index_file(index_path: Path) -> dict[str, Any]:
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"sorters": [], "fallback": "raw"}
    if not isinstance(data, dict):
        return {"sorters": [], "fallback": "raw"}
    sorters = []
    for sorter in data.get("sorters") if isinstance(data.get("sorters"), list) else []:
        if not isinstance(sorter, dict):
            continue
        item = dict(sorter)
        item["_sorter_base_dir"] = str(index_path.parent)
        item["_sorter_index"] = str(index_path)
        sorters.append(item)
    return {"sorters": sorters, "fallback": data.get("fallback", "raw")}


def find_sorter_for_item(
    item: dict[str, Any],
    index_config: dict[str, Any],
) -> dict[str, Any] | None:
    sorters = index_config.get("sorters", [])
    function_id = item.get("function_id")
    result_key = item.get("result_key")

    for sorter in sorters:
        if isinstance(sorter, dict) and sorter.get("function_id") == function_id:
            return sorter
    for sorter in sorters:
        if isinstance(sorter, dict) and sorter.get("result_key") == result_key:
            return sorter
    return None


def sort_raw_output_item(item: dict[str, Any]) -> dict[str, Any]:
    index_config = load_raw_sorting_index()
    sorter = find_sorter_for_item(item, index_config)
    base = _base_item(item)
    if sorter is None:
        return {
            **base,
            "sort_status": "raw_fallback",
            "sorter": None,
            "ai_payload": {
                "raw_output": item,
                "limitations": [
                    "No raw sorting function was configured; raw output is returned."
                ],
            },
        }

    sorter_file = str(sorter.get("sorter_file", ""))
    callable_name = str(sorter.get("callable", "sort_output"))
    sorter_base_dir = Path(str(sorter.get("_sorter_base_dir") or RAW_SORTING_DIR))
    try:
        fn = _load_sorter(sorter_file, callable_name, sorter_base_dir)
        payload = fn(item)
        if not isinstance(payload, dict):
            raise TypeError("sorter callable must return dict")
    except Exception as exc:
        return {
            **base,
            "sort_status": "sort_error_fallback",
            "sorter": sorter_file,
            "sort_error": str(exc),
            "ai_payload": {
                "raw_output": item,
                "limitations": ["Raw sorting function failed; raw output is returned."],
            },
        }

    return {
        **base,
        "sort_status": "sorted",
        "sorter": sorter_file,
        "ai_payload": payload,
    }


def sort_raw_outputs(raw_outputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": raw_outputs.get("session_id", ""),
        "items": [
            sort_raw_output_item(item)
            for item in raw_outputs.get("items", [])
            if isinstance(item, dict)
        ],
    }


def _base_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "raw_output_id": item.get("raw_output_id", ""),
        "index": item.get("index", 0),
        "function_id": item.get("function_id", ""),
        "function_name": item.get("function_name", item.get("function_id", "")),
        "result_key": item.get("result_key", ""),
        "status": item.get("status", ""),
    }


def _load_sorter(
    sorter_file: str,
    callable_name: str,
    base_dir: Path | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    path = _resolve_sorter_file(sorter_file, base_dir)
    spec = importlib.util.spec_from_file_location(f"raw_sorter_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError("sorter could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, callable_name)
    if not callable(fn):
        raise TypeError("sorter target is not callable")
    return fn


def _resolve_sorter_file(sorter_file: str, base_dir: Path | None = None) -> Path:
    if not sorter_file or Path(sorter_file).is_absolute():
        raise ValueError("invalid sorter_file")
    if ".." in Path(sorter_file).parts:
        raise ValueError("invalid sorter_file")
    if Path(sorter_file).suffix.lower() != ".py":
        raise ValueError("sorter_file must be .py")
    root = (base_dir or RAW_SORTING_DIR).resolve()
    path = (root / sorter_file).resolve()
    if root != path.parent and root not in path.parents:
        raise ValueError("sorter_file outside raw sorting directory")
    return path
