"""Shared flow validation helpers for custom component policy enforcement."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from lfx.log.logger import logger
from lfx.utils.component_aliases import get_component_type_aliases

INITIALIZING_COMPONENT_TEMPLATES_MESSAGE = (
    "Flow build blocked: component templates are still initializing. Please try again in a few seconds."
)
SETTINGS_SERVICE_REQUIRED_MESSAGE = "Settings service must be initialized before validating flows."

# Built-in components that execute arbitrary Python supplied through their *input fields*
# (not the validated class `code` field). Their class-code hash is valid, so they pass the
# allow_custom_components policy, yet they are effectively a custom-code-authoring surface.
# Identifiers include class names plus their `name`/`display_name` aliases so the check
# matches whatever value the node carries in ``data.type``. Enforced when
# ``block_code_interpreter_components`` is enabled. Keep this set in sync with the components
# that call exec()/eval() on user input under src/lfx/src/lfx/components/.
CODE_EXECUTION_COMPONENT_TYPES: frozenset[str] = frozenset(
    {
        # tools/python_code_structured_tool.py — exec(self.tool_code, globals()).
        # NOTE: list EVERY alias (class name, ``name``, ``display_name``) of each component:
        # a node's ``data.type`` may be any alias under which the code hash is registered, so a
        # missing alias (e.g. the display_name) lets a hash-valid node slip past this block.
        "PythonCodeStructuredTool",
        "Python Code Structured",  # display_name — must be listed or the block is bypassable
        # utilities/python_repl_core.py — Python Interpreter (exec via PythonREPL)
        "PythonREPLComponent",
        "Python Interpreter",
        # tools/python_repl.py — Python REPL tool (exec via PythonREPL)
        "PythonREPLToolComponent",
        "PythonREPLTool",
        "Python REPL",
        # prototypes/python_function.py — exec of user `function_code` via create_function()
        "PythonFunctionComponent",
        "PythonFunction",
        "Python Function",
        # llm_operations/lambda_filter.py — eval() of an LLM-generated lambda
        "LambdaFilterComponent",
        "Smart Transform",
        # codeagents/codeact_agent_smolagents.py — runs LLM-generated Python in-process
        # via smolagents' LocalPythonExecutor, which is explicitly NOT a security sandbox.
        "CodeActAgentSmolagents",
        "CodeAct Agent (Smolagents)",
        # codeagents/open_ds_star_agent.py — DS-Star ExecutorNode runs LLM-generated code
        # through a bare exec(code, scope, scope) (no restricted interpreter at all).
        "OpenDsStarAgent",
        "OpenDsStar Agent",
    }
)


class CustomComponentValidationError(ValueError):
    """Raised when a flow fails custom-component policy validation.

    Subclasses ValueError so existing ``except ValueError`` handlers
    still catch it, but callers can catch this specifically to
    distinguish policy errors from other ValueErrors.
    """


def _compute_code_hash(code: str) -> str:
    """Compute the 12-char SHA256 prefix used by the component index."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:12]


def _normalize_flow_data(flow_data: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Normalize wrapped flow payloads to the raw graph data shape."""
    if flow_data is None:
        return None

    normalized: Mapping[str, Any] = flow_data
    if "data" in normalized and isinstance(normalized["data"], Mapping):
        normalized = normalized["data"]

    return normalized if isinstance(normalized, dict) else dict(normalized)


def _extract_graph_payload(graph: Any) -> Mapping[str, Any] | None:
    """Extract a graph payload from a Graph-like object for policy validation.

    Only uses ``raw_graph_data`` — the authoritative, unmodified graph
    payload stored at construction time.  We intentionally avoid falling
    back to ``graph.dump()`` because dump may omit nodes or return
    a reconstructed payload that doesn't reflect the original flow
    definition, which could silently bypass validation.
    """
    raw_graph_data = getattr(graph, "raw_graph_data", None)
    if isinstance(raw_graph_data, Mapping):
        return raw_graph_data

    return None


def _extract_flow_data(target: Mapping[str, Any] | Any | None) -> dict[str, Any] | None:
    """Normalize a flow payload or graph-like object to raw graph data."""
    if isinstance(target, Mapping) or target is None:
        return _normalize_flow_data(target)

    return _normalize_flow_data(_extract_graph_payload(target))


def collect_component_hash_lookups(
    all_types_dict: Mapping[str, Any],
) -> tuple[dict[str, set[str]], set[str]]:
    """Build code-hash lookups for components and their aliases.

    Each component type maps to a *set* of valid hashes so that
    custom components loaded from ``components_path`` can coexist
    with built-in components of the same name.
    """
    type_to_hash: dict[str, set[str]] = {}
    all_hashes: set[str] = set()

    for category_components in all_types_dict.values():
        if not isinstance(category_components, Mapping):
            continue

        for component_name, component_data in category_components.items():
            if not isinstance(component_data, Mapping):
                continue

            metadata = component_data.get("metadata")
            if not isinstance(metadata, Mapping):
                continue

            code_hash = metadata.get("code_hash")
            if not isinstance(code_hash, str) or not code_hash:
                continue

            all_hashes.add(code_hash)
            for alias in get_component_type_aliases(component_name, component_data):
                type_to_hash.setdefault(alias, set()).add(code_hash)

    return type_to_hash, all_hashes


def _get_invalid_components(
    nodes: list[dict],
    type_to_current_hash: dict[str, set[str]],
) -> tuple[list[str], list[str]]:
    """Walk nodes and classify invalid components."""
    blocked: list[str] = []
    outdated: list[str] = []

    for node in nodes:
        node_data = node.get("data", {})
        node_info = node_data.get("node", {})

        component_type = node_data.get("type")
        if not component_type:
            continue

        node_template = node_info.get("template", {})
        node_code_field = node_template.get("code", {})
        node_code = node_code_field.get("value") if isinstance(node_code_field, dict) else None

        if not node_code:
            continue

        display_name = node_info.get("display_name") or component_type
        node_id = node_data.get("id") or node.get("id", "unknown")
        label = f"{display_name} ({node_id})"

        expected_hashes = type_to_current_hash.get(component_type)
        if expected_hashes is None:
            blocked.append(label)
        else:
            node_hash = _compute_code_hash(node_code)
            if node_hash not in expected_hashes:
                outdated.append(label)

        flow_data = node_info.get("flow", {})
        if isinstance(flow_data, dict):
            nested_data = flow_data.get("data", {})
            nested_nodes = nested_data.get("nodes", [])
            if nested_nodes:
                nested_blocked, nested_outdated = _get_invalid_components(
                    nested_nodes,
                    type_to_current_hash,
                )
                blocked.extend(nested_blocked)
                outdated.extend(nested_outdated)

    return blocked, outdated


def _find_code_execution_components(nodes: list[dict]) -> list[str]:
    """Return labels for every node whose type is a built-in code-execution component.

    Recurses into nested/sub-flow node payloads so a code-execution component cannot be
    hidden inside an embedded flow definition.
    """
    found: list[str] = []

    for node in nodes:
        node_data = node.get("data", {})
        node_info = node_data.get("node", {})

        component_type = node_data.get("type")
        if isinstance(component_type, str) and component_type in CODE_EXECUTION_COMPONENT_TYPES:
            display_name = node_info.get("display_name") or component_type
            node_id = node_data.get("id") or node.get("id", "unknown")
            found.append(f"{display_name} ({node_id})")

        flow_data = node_info.get("flow", {})
        if isinstance(flow_data, dict):
            nested_nodes = flow_data.get("data", {}).get("nodes", [])
            if nested_nodes:
                found.extend(_find_code_execution_components(nested_nodes))

    return found


def check_code_execution_components_and_raise(flow_data: dict | None) -> None:
    """Block flows containing built-in arbitrary-code-execution components.

    Called when ``block_code_interpreter_components`` is enabled. Raises
    :class:`CustomComponentValidationError` if any code-execution component is present.
    """
    if not flow_data:
        return

    nodes = flow_data.get("nodes", [])
    if not nodes:
        return

    found = _find_code_execution_components(nodes)
    if found:
        names = ", ".join(found)
        logger.warning(f"Flow build blocked: code-execution components are disabled: {names}")
        message = f"Flow build blocked: code-execution components are not allowed: {names}"
        raise CustomComponentValidationError(message)


def code_hash_matches_any_template(code: str, all_known_hashes: set[str]) -> bool:
    """Check whether code matches any known component template hash."""
    return _compute_code_hash(code) in all_known_hashes


def check_flow_and_raise(
    flow_data: dict | None,
    *,
    allow_custom_components: bool,
    type_to_current_hash: dict[str, set[str]] | None = None,
) -> None:
    """Validate flow component code against known server templates."""
    if allow_custom_components or not flow_data:
        return

    nodes = flow_data.get("nodes", [])
    if not nodes:
        return

    if type_to_current_hash is None:
        logger.error(
            "Flow validation requested but component hash lookups are not yet loaded. "
            "Blocking execution as a safety measure."
        )
        raise CustomComponentValidationError(INITIALIZING_COMPONENT_TEMPLATES_MESSAGE)

    blocked, outdated = _get_invalid_components(nodes, type_to_current_hash)

    if blocked:
        blocked_names = ", ".join(blocked)
        logger.warning(f"Flow build blocked: unrecognized component code: {blocked_names}")
        message = f"Flow build blocked: custom components are not allowed: {blocked_names}"
        raise CustomComponentValidationError(message)

    if outdated:
        outdated_names = ", ".join(outdated)
        logger.warning(f"Flow build blocked: outdated components must be updated: {outdated_names}")
        message = f"Flow build blocked: outdated components must be updated before running: {outdated_names}"
        raise CustomComponentValidationError(message)


def get_component_hash_lookups_for_validation() -> dict[str, set[str]] | None:
    """Return the cached component hashes, building them synchronously if possible."""
    from lfx.interface.components import component_cache

    if component_cache.type_to_current_hash is None and component_cache.all_types_dict is not None:
        type_to_hash, all_hashes = collect_component_hash_lookups(component_cache.all_types_dict)
        component_cache.type_to_current_hash = type_to_hash
        component_cache.all_known_hashes = all_hashes

    return component_cache.type_to_current_hash


def validate_flow_for_current_settings(target: Mapping[str, Any] | Any | None) -> None:
    """Enforce custom-component policy for a payload or graph-like object."""
    from lfx.services.deps import get_settings_service

    settings_service = get_settings_service()
    if settings_service is None:
        raise RuntimeError(SETTINGS_SERVICE_REQUIRED_MESSAGE)

    allow_custom_components = settings_service.settings.allow_custom_components
    block_code_interpreter_components = getattr(settings_service.settings, "block_code_interpreter_components", False)
    normalized_flow_data = _extract_flow_data(target)

    # If a blocking policy is active and we received a target but couldn't extract any flow
    # data from it, fail fast rather than silently skipping validation — the caller passed
    # something we can't verify.
    if (not allow_custom_components or block_code_interpreter_components) and (
        target is not None and normalized_flow_data is None
    ):
        msg = (
            "Flow validation failed: could not extract graph data from the provided target. "
            "Ensure the flow payload or Graph object contains valid graph data."
        )
        raise CustomComponentValidationError(msg)

    if block_code_interpreter_components:
        check_code_execution_components_and_raise(normalized_flow_data)

    type_to_current_hash = get_component_hash_lookups_for_validation() if not allow_custom_components else None

    check_flow_and_raise(
        normalized_flow_data,
        allow_custom_components=allow_custom_components,
        type_to_current_hash=type_to_current_hash,
    )


async def ensure_component_hash_lookups_loaded() -> dict[str, str] | None:
    """Ensure component hash lookups are available for CLI/runtime validation."""
    from lfx.interface.components import component_cache, get_and_cache_all_types_dict
    from lfx.services.deps import get_settings_service

    settings_service = get_settings_service()
    if settings_service is None:
        raise RuntimeError(SETTINGS_SERVICE_REQUIRED_MESSAGE)

    if not settings_service.settings.allow_custom_components and component_cache.type_to_current_hash is None:
        try:
            await get_and_cache_all_types_dict(settings_service)
        except Exception as exc:
            logger.warning("Failed to populate component template hash lookups", exc_info=exc)
            raise

    return component_cache.type_to_current_hash
