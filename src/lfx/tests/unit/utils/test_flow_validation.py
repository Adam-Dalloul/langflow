"""Unit tests for LFX flow validation helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from lfx.utils.flow_validation import (
    CustomComponentValidationError,
    ensure_component_hash_lookups_loaded,
    validate_flow_for_current_settings,
)


def _code_interpreter_raw_graph(component_type: str = "PythonREPLComponent") -> dict:
    """A graph whose single node is a built-in code-execution component."""
    return {
        "nodes": [
            {
                "id": "py-1",
                "data": {
                    "id": "py-1",
                    "type": component_type,
                    "node": {
                        "display_name": "Python Interpreter",
                        "template": {"code": {"value": "print('builtin component')"}},
                    },
                },
            }
        ],
        "edges": [],
    }


def _blocked_raw_graph() -> dict:
    return {
        "nodes": [
            {
                "id": "node-1",
                "data": {
                    "id": "node-1",
                    "type": "TotallyCustom",
                    "node": {
                        "display_name": "Blocked Node",
                        "template": {
                            "code": {"value": "print('blocked')"},
                        },
                    },
                },
            }
        ],
        "edges": [],
    }


@pytest.mark.asyncio
async def test_ensure_component_hash_lookups_loaded_requires_settings_service(monkeypatch):
    """Hash warmup should fail loudly when the settings service is unavailable."""
    monkeypatch.setattr("lfx.services.deps.get_settings_service", lambda: None)

    with pytest.raises(RuntimeError, match="Settings service must be initialized"):
        await ensure_component_hash_lookups_loaded()


@pytest.mark.asyncio
async def test_ensure_component_hash_lookups_loaded_surfaces_loader_failures(monkeypatch):
    """Loader failures should not be masked as a transient initialization state."""
    from lfx.interface.components import component_cache

    settings_service = SimpleNamespace(
        settings=SimpleNamespace(allow_custom_components=False),
    )
    monkeypatch.setattr("lfx.services.deps.get_settings_service", lambda: settings_service)
    monkeypatch.setattr(component_cache, "type_to_current_hash", None)

    with (
        patch(
            "lfx.interface.components.get_and_cache_all_types_dict",
            new=AsyncMock(side_effect=RuntimeError("component import failed")),
        ),
        pytest.raises(RuntimeError, match="component import failed"),
    ):
        await ensure_component_hash_lookups_loaded()


def test_validate_flow_for_current_settings_requires_settings_service(monkeypatch):
    """Unified validation should also require the settings service."""
    monkeypatch.setattr("lfx.services.deps.get_settings_service", lambda: None)
    graph = SimpleNamespace(raw_graph_data=_blocked_raw_graph())

    with pytest.raises(RuntimeError, match="Settings service must be initialized"):
        validate_flow_for_current_settings(graph)


@pytest.mark.parametrize(
    "component_type",
    [
        "PythonREPLComponent",
        "PythonCodeStructuredTool",
        "PythonREPLToolComponent",
        "LambdaFilterComponent",
        "Smart Transform",  # alias must also be caught
    ],
)
def test_block_code_interpreter_components_blocks_flow(monkeypatch, component_type):
    """When the flag is on, flows with code-execution components are blocked."""
    settings_service = SimpleNamespace(
        settings=SimpleNamespace(
            allow_custom_components=True,
            block_code_interpreter_components=True,
        ),
    )
    monkeypatch.setattr("lfx.services.deps.get_settings_service", lambda: settings_service)
    graph = SimpleNamespace(raw_graph_data=_code_interpreter_raw_graph(component_type))

    with pytest.raises(CustomComponentValidationError, match="code-execution components are not allowed"):
        validate_flow_for_current_settings(graph)


def test_block_code_interpreter_components_disabled_allows_flow(monkeypatch):
    """With the flag off (default), code-execution components are permitted."""
    settings_service = SimpleNamespace(
        settings=SimpleNamespace(
            allow_custom_components=True,
            block_code_interpreter_components=False,
        ),
    )
    monkeypatch.setattr("lfx.services.deps.get_settings_service", lambda: settings_service)
    graph = SimpleNamespace(raw_graph_data=_code_interpreter_raw_graph())

    # Should not raise.
    validate_flow_for_current_settings(graph)


def test_block_code_interpreter_components_detects_nested_flow(monkeypatch):
    """A code-execution component hidden inside a nested/sub-flow must still be caught."""
    settings_service = SimpleNamespace(
        settings=SimpleNamespace(
            allow_custom_components=True,
            block_code_interpreter_components=True,
        ),
    )
    monkeypatch.setattr("lfx.services.deps.get_settings_service", lambda: settings_service)
    nested = _code_interpreter_raw_graph()
    outer = {
        "nodes": [
            {
                "id": "wrapper",
                "data": {
                    "id": "wrapper",
                    "type": "SomeBenignComponent",
                    "node": {"flow": {"data": nested}},
                },
            }
        ],
        "edges": [],
    }
    graph = SimpleNamespace(raw_graph_data=outer)

    with pytest.raises(CustomComponentValidationError, match="code-execution components are not allowed"):
        validate_flow_for_current_settings(graph)
