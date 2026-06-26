from __future__ import annotations

from typing import Any


def sort_output(item: dict[str, Any]) -> dict[str, Any]:
    result_key = str(item.get("result_key") or "")
    output = item.get("output") if isinstance(item.get("output"), dict) else {}
    if output.get("status") == "error":
        return _error_payload(result_key, output)
    data = output.get("data") if isinstance(output.get("data"), dict) else {}

    if result_key == "malwarebazaar_download":
        source = data.get("source_metadata") if isinstance(data.get("source_metadata"), dict) else {}
        cleanup = data.get("cleanup") if isinstance(data.get("cleanup"), dict) else {}
        return {
            "summary": f"MalwareBazaar sample downloaded: {source.get('signature') or 'unknown signature'} {data.get('sha256', '')}",
            "key_fields": {
                "provider": data.get("provider", ""),
                "sha256": data.get("sha256", ""),
                "filename": data.get("filename", ""),
                "sample_size": data.get("sample_size", 0),
                "file_type": source.get("file_type", ""),
                "signature": source.get("signature", ""),
                "tags": _string_list(source.get("tags"))[:10],
                "first_seen": source.get("first_seen", ""),
                "candidate_offset": data.get("candidate_offset", 0),
                "activate_sample_path": bool(data.get("activate_sample_path")),
                "cleanup_required": bool(cleanup.get("delete_after_analysis")),
                "cleanup_paths_count": len(_string_list(cleanup.get("paths"))),
            },
            "warnings": [
                "Downloaded sample is local evidence only; execution is a separate VM action.",
                "Local filesystem paths are intentionally summarized instead of printed.",
            ],
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "hash":
        return {
            "summary": f"Hashes computed for sample: sha256={data.get('sha256', '')}",
            "key_fields": {
                "md5": data.get("md5", ""),
                "sha1": data.get("sha1", ""),
                "sha256": data.get("sha256", ""),
            },
            "limitations": [],
        }

    if result_key == "file_type":
        return {
            "summary": f"File type detected as {data.get('detected_type', 'unknown')}.",
            "key_fields": {
                "detected_type": data.get("detected_type", "unknown"),
                "extension": data.get("extension", ""),
                "mime_like": data.get("mime_like", ""),
            },
            "limitations": ["Lightweight type detection only."],
        }

    if result_key == "multi_format_parser":
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        return {
            "summary": f"Container/header format detected as {data.get('detected_format', 'unknown')}.",
            "key_fields": {
                "detected_format": data.get("detected_format", "unknown"),
                "filename": metadata.get("filename", ""),
                "extension": metadata.get("extension", ""),
                "size": metadata.get("size", 0),
                "header_hex": metadata.get("header_hex", ""),
            },
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "byte_stats":
        entropy = data.get("entropy_estimate", 0)
        return {
            "summary": f"Byte statistics collected; entropy={entropy}.",
            "key_fields": {
                "file_size": data.get("file_size", 0),
                "entropy_estimate": entropy,
                "printable_ascii_ratio": data.get("printable_ascii_ratio", 0),
                "null_byte_count": data.get("null_byte_count", 0),
                "header_hex": data.get("header_hex", ""),
            },
            "evidence_hints": _entropy_hints(entropy),
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "pe_deep_parse":
        headers = data.get("headers") if isinstance(data.get("headers"), dict) else {}
        counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
        directories = data.get("directories") if isinstance(data.get("directories"), dict) else {}
        sections = [section for section in data.get("sections", []) if isinstance(section, dict)]
        imports = [entry for entry in data.get("imports", []) if isinstance(entry, dict)]
        clr = directories.get("clr_runtime") if isinstance(directories.get("clr_runtime"), dict) else {}
        return {
            "summary": (
                f"PE parsed: {data.get('format', '')}, machine={headers.get('machine', '')}, "
                f"sections={counts.get('sections', 0)}, imports={counts.get('import_functions', 0)}."
            ),
            "key_fields": {
                "format": data.get("format", ""),
                "machine": headers.get("machine", ""),
                "subsystem": headers.get("subsystem", ""),
                "entry_point_section": headers.get("entry_point_section", ""),
                "size_of_image": headers.get("size_of_image", 0),
                "clr_runtime_present": bool(clr.get("present")),
                "overlay": data.get("overlay", {}),
                "counts": counts,
                "import_dlls": [str(entry.get("dll", "")) for entry in imports[:10]],
            },
            "high_entropy_sections": [
                {
                    "name": section.get("name", ""),
                    "entropy": section.get("entropy", 0),
                    "raw_size": section.get("raw_size", 0),
                    "characteristics": section.get("characteristics", []),
                }
                for section in sections
                if _float(section.get("entropy")) >= 7.2
            ][:10],
            "sections_sample": [
                {
                    "name": section.get("name", ""),
                    "entropy": section.get("entropy", 0),
                    "raw_size": section.get("raw_size", 0),
                    "characteristics": section.get("characteristics", []),
                }
                for section in sections[:8]
            ],
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "packer_detection":
        indicators = [item for item in data.get("indicators", []) if isinstance(item, dict)]
        return {
            "summary": (
                f"Packer/obfuscation heuristic: likely_packed={bool(data.get('likely_packed'))}, "
                f"confidence={data.get('confidence', 'low')}, score={data.get('score', 0)}."
            ),
            "key_fields": {
                "likely_packed": bool(data.get("likely_packed")),
                "confidence": data.get("confidence", "low"),
                "score": data.get("score", 0),
                "file_entropy": data.get("file_entropy", 0),
                "counts": data.get("counts", {}),
            },
            "indicators": indicators[:12],
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "local_sample_cleanup":
        counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
        return {
            "summary": (
                f"Local sample cleanup completed: deleted={counts.get('deleted', 0)}, "
                f"missing={counts.get('missing', 0)}, refused={counts.get('refused', 0)}."
            ),
            "key_fields": {
                "dry_run": bool(data.get("dry_run")),
                "counts": counts,
                "deleted": _string_list(data.get("deleted"))[:20],
                "missing": _string_list(data.get("missing"))[:20],
                "refused": data.get("refused", [])[:20] if isinstance(data.get("refused"), list) else [],
                "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
            },
            "warnings": ["Host cleanup only; guest VM files are not removed by this function."],
            "limitations": _string_list(data.get("limitations")),
        }

    return {
        "summary": f"Static triage output for {result_key}.",
        "key_fields": data,
        "limitations": ["No specialized branch matched this result_key."],
    }


def _error_payload(result_key: str, output: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary": f"{result_key} returned an error.",
        "error": output.get("error", {}),
        "limitations": ["Sorter returned compact error view."],
    }


def _entropy_hints(value: Any) -> list[str]:
    entropy = _float(value)
    if entropy >= 7.2:
        return ["High entropy can indicate packing, encryption, compression, or dense embedded data."]
    if entropy >= 6.8:
        return ["Elevated entropy; review with packer detection and section-level evidence."]
    return []


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []
