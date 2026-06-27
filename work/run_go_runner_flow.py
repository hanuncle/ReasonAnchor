from __future__ import annotations

import argparse
import json
import mimetypes
import pathlib
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


TERMINAL_STATUSES = {"completed", "failed", "canceled"}


def request_json(method: str, url: str, payload: Any | None = None) -> dict[str, Any]:
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} returned {exc.code}: {body}") from exc


def upload_file(api_base: str, sample_path: pathlib.Path) -> dict[str, Any]:
    boundary = f"----sfp-boundary-{uuid.uuid4().hex}"
    content_type = mimetypes.guess_type(sample_path.name)[0] or "application/octet-stream"
    file_bytes = sample_path.read_bytes()
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{sample_path.name}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = head + file_bytes + tail
    request = urllib.request.Request(
        f"{api_base}/api/sessions/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"upload returned {exc.code}: {body}") from exc


def compact_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    nodes = snapshot.get("nodes") if isinstance(snapshot.get("nodes"), dict) else {}
    counts: dict[str, int] = {}
    for node in nodes.values():
        if isinstance(node, dict):
            status = str(node.get("status") or "unknown")
            counts[status] = counts.get(status, 0) + 1
    failed_node = snapshot.get("failed_node") if isinstance(snapshot.get("failed_node"), dict) else None
    return {
        "job_id": snapshot.get("job_id"),
        "status": snapshot.get("status"),
        "counts": counts,
        "completed_nodes": snapshot.get("completed_nodes", []),
        "running_nodes": [
            node.get("node_id") for node in snapshot.get("running_nodes", []) if isinstance(node, dict)
        ],
        "failed_node": failed_node,
        "stopped_reason": snapshot.get("stopped_reason"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--api-base", default="http://127.0.0.1:8111")
    parser.add_argument("--runner-base", default="http://127.0.0.1:8112")
    parser.add_argument("--module-id", default="malware_analysis")
    parser.add_argument("--flow-id", default="interactive_single_sample_full")
    parser.add_argument("--dynamic-action-id", default="malware.dynamic_quick_run")
    parser.add_argument("--confirm-restore", default="")
    parser.add_argument("--confirm-execute", default="")
    parser.add_argument("--max-parallel", type=int, default=0)
    parser.add_argument("--max-wait-seconds", type=int, default=900)
    parser.add_argument("--poll-seconds", type=int, default=5)
    args = parser.parse_args()

    sample_path = pathlib.Path(args.sample)
    if not sample_path.is_file():
        raise SystemExit(f"sample not found: {sample_path}")

    api_base = args.api_base.rstrip("/")
    runner_base = args.runner_base.rstrip("/")
    started_at = time.perf_counter()
    upload = upload_file(api_base, sample_path)
    session_id = str(upload.get("session_id") or "")
    if not session_id:
        raise SystemExit(f"upload response has no session_id: {upload}")
    print(json.dumps({"event": "uploaded", "session_id": session_id, "filename": sample_path.name}, ensure_ascii=False), flush=True)

    preview_body: dict[str, Any] = {
        "flow_id": args.flow_id,
        "session_id": session_id,
        "params": {},
    }
    if args.dynamic_action_id:
        preview_body["params"]["dynamic_action_id"] = args.dynamic_action_id
    if args.confirm_restore:
        preview_body["params"]["confirm_restore"] = args.confirm_restore
    if args.confirm_execute:
        preview_body["params"]["confirm_execute"] = args.confirm_execute
    preview = request_json(
        "POST",
        f"{api_base}/api/modules/{args.module_id}/runner/flows/preview",
        preview_body,
    )
    if not preview.get("ready"):
        print(json.dumps({"event": "preview_not_ready", "preview": preview}, ensure_ascii=False, indent=2), flush=True)
        return 2
    plan = preview["runner_plan"]
    if args.max_parallel > 0:
        plan.setdefault("execution", {})["max_parallel"] = args.max_parallel
    nodes = plan.get("plan", {}).get("nodes", [])
    locked_nodes = [
        {"node_id": node.get("node_id"), "function_id": node.get("function_id"), "locks": node.get("resource_locks")}
        for node in nodes
        if isinstance(node, dict) and node.get("resource_locks")
    ]
    print(
        json.dumps(
            {
                "event": "preview_ready",
                "flow_id": args.flow_id,
                "nodes": len(nodes),
                "dynamic_action_id": args.dynamic_action_id,
                "max_parallel": plan.get("execution", {}).get("max_parallel"),
                "locked_nodes": locked_nodes,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )

    job = request_json("POST", f"{runner_base}/jobs", {"runner_plan": plan})
    job_id = str(job.get("job_id") or "")
    if not job_id:
        raise SystemExit(f"runner response has no job_id: {job}")
    print(json.dumps({"event": "submitted", "snapshot": compact_snapshot(job)}, ensure_ascii=False), flush=True)

    deadline = time.time() + args.max_wait_seconds
    last_status = ""
    last_counts: dict[str, int] = {}
    while time.time() < deadline:
        time.sleep(args.poll_seconds)
        snapshot = request_json("GET", f"{runner_base}/jobs/{job_id}")
        compact = compact_snapshot(snapshot)
        status = str(compact.get("status") or "")
        counts = compact.get("counts") if isinstance(compact.get("counts"), dict) else {}
        if status != last_status or counts != last_counts:
            print(json.dumps({"event": "status", "snapshot": compact}, ensure_ascii=False), flush=True)
            last_status = status
            last_counts = dict(counts)
        if status in TERMINAL_STATUSES:
            elapsed_seconds = time.perf_counter() - started_at
            serial_node_seconds = sum(
                float(node.get("duration_ms") or 0) / 1000.0
                for node in snapshot.get("nodes", {}).values()
                if isinstance(node, dict)
            )
            improvement = (
                max(0.0, (serial_node_seconds - elapsed_seconds) / serial_node_seconds)
                if serial_node_seconds > 0
                else 0.0
            )
            print(
                json.dumps(
                    {
                        "event": "timing",
                        "elapsed_seconds": round(elapsed_seconds, 3),
                        "serial_node_seconds": round(serial_node_seconds, 3),
                        "estimated_saved_seconds": round(serial_node_seconds - elapsed_seconds, 3),
                        "estimated_efficiency_improvement_percent": round(improvement * 100, 2),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
            return 0 if status == "completed" else 3
    snapshot = request_json("GET", f"{runner_base}/jobs/{job_id}")
    print(json.dumps({"event": "timeout", "snapshot": compact_snapshot(snapshot)}, ensure_ascii=False), flush=True)
    return 4


if __name__ == "__main__":
    sys.exit(main())
