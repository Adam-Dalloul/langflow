"""Coordinator: graph in, streaming step results out."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from lfx.execution.partitioner import identity_partition
from lfx.execution.types import RunComplete, StepResult
from lfx.services.capability.protocols import RESERVED_CAPABILITY_RUNTIME_OPTION_KEYS

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from lfx.execution.registry import ExecutorRegistry
    from lfx.services.capability import CapabilityService


class Coordinator:
    def __init__(
        self,
        *,
        registry: ExecutorRegistry,
        executor_kind: str = "in-process",
        capability_service: CapabilityService | None = None,
    ) -> None:
        self._registry = registry
        self._executor_kind = executor_kind
        self._capability_service = capability_service

    async def run(
        self,
        graph: Any,
        *,
        inputs: list[dict[str, Any]],
        **runtime_options: Any,
    ) -> AsyncIterator[StepResult | RunComplete]:
        options = self._without_capability_metadata(runtime_options)
        units = identity_partition(graph, inputs=inputs, runtime_options=options)
        if self._capability_service is not None and not self._capability_service.is_passthrough:
            decision = self._capability_service.route(
                graph,
                user_id=self._context_value(graph, options, "user_id", "lfx_user_id"),
                flow_id=self._context_value(graph, options, "flow_id", "lfx_flow_id"),
                run_id=self._context_value(graph, options, "run_id", "lfx_run_id"),
                default_executor_kind=self._executor_kind,
                scopes=self._capability_scopes(options),
                runtime_options=options,
            )
            units = [
                replace(
                    unit,
                    executor_kind=decision.executor_kind,
                    runtime_options={
                        **self._without_capability_metadata(unit.runtime_options),
                        **decision.runtime_options,
                    },
                )
                for unit in units
            ]
        for unit in units:
            executor = self._registry.get(unit.executor_kind or self._executor_kind)
            inner = executor.execute(unit)
            try:
                async for item in inner:
                    yield item
            finally:
                aclose = getattr(inner, "aclose", None)
                if aclose is not None:
                    await aclose()

    async def run_to_completion(
        self,
        graph: Any,
        *,
        inputs: list[dict[str, Any]],
        **runtime_options: Any,
    ) -> list[Any]:
        async for item in self.run(graph, inputs=inputs, **runtime_options):
            if isinstance(item, RunComplete):
                return item.outputs
        msg = "Executor stream ended without a RunComplete"
        raise RuntimeError(msg)

    async def stream(
        self,
        graph: Any,
        *,
        inputs: list[dict[str, Any]] | None = None,
        **runtime_options: Any,
    ) -> AsyncIterator[Any]:
        inner = self.run(graph, inputs=inputs or [], **runtime_options)
        try:
            async for item in inner:
                if isinstance(item, StepResult):
                    yield item.payload
        finally:
            await inner.aclose()

    @staticmethod
    def _context_value(graph: Any, runtime_options: dict[str, Any], *names: str) -> str | None:
        for name in names:
            value = runtime_options.get(name)
            if value is not None:
                return str(value)
            value = getattr(graph, name, None)
            if value is not None:
                return str(value)
        return None

    @staticmethod
    def _capability_scopes(runtime_options: dict[str, Any]) -> Sequence[str]:
        scopes = runtime_options.get("capability_scopes", runtime_options.get("lfx_capability_scopes", ()))
        if scopes is None:
            return ()
        if isinstance(scopes, str):
            return (scopes,)
        return tuple(scopes)

    @staticmethod
    def _without_capability_metadata(runtime_options: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value for key, value in runtime_options.items() if key not in RESERVED_CAPABILITY_RUNTIME_OPTION_KEYS
        }
