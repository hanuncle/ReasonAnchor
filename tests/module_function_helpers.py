from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import TypeVar

import pytest

from security_function_platform.core.function_base import AnalysisFunction

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVERSE_FUNCTION_DIR = PROJECT_ROOT / "modules" / "reverse" / "functions"

T = TypeVar("T", bound=type[AnalysisFunction])


def reverse_function_module(filename: str) -> ModuleType:
    path = REVERSE_FUNCTION_DIR / filename
    if not path.is_file():
        pytest.skip(
            "reverse module is not included in this platform-only checkout",
            allow_module_level=True,
        )
    spec = importlib.util.spec_from_file_location(f"test_reverse_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Could not load reverse function module: {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reverse_function_class(filename: str, class_name: str) -> T:
    module = reverse_function_module(filename)
    candidate = getattr(module, class_name)
    if not issubclass(candidate, AnalysisFunction):
        raise AssertionError(f"Not an AnalysisFunction class: {class_name}")
    return candidate
