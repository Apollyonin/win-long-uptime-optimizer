"""Base optimizer contract and shared execution context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from winopt.config import OptimizerConfig
from winopt.models import ActionResult, GuardDecision, PolicyState, SystemSnapshot


@dataclass
class OptimizationContext:
    mode: str  # "scheduled" | "manual" | "boost" | "dry_run"
    dry_run: bool
    guard: GuardDecision
    t0: SystemSnapshot
    policy: PolicyState
    config: OptimizerConfig


class BaseOptimizer(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, ctx: OptimizationContext) -> ActionResult:
        """Execute optimization or return dry-run/skipped summary."""
        raise NotImplementedError
