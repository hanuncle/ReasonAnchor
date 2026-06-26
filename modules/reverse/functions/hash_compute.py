from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_CHUNK_SIZE = 1024 * 1024


class HashComputeFunction(AnalysisFunction):
    id = "hash.compute"
    name = "Hash compute"
    category = "static"
    result_key = "hash"

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")

        path = Path(sample_path)
        if not path.is_file():
            return self._error("file_not_found", "sample file was not found")

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        try:
            with path.open("rb") as sample:
                while True:
                    chunk = sample.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except OSError:
            return self._error("read_failed", "sample file could not be read")

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "md5": md5.hexdigest(),
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
            },
        )

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
