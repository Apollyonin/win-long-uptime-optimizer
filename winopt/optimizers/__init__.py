"""Modular safe Windows optimization plugins."""

from winopt.optimizers.base import BaseOptimizer
from winopt.optimizers.cpu_power import CpuPowerOptimizer
from winopt.optimizers.gpu_readiness import GpuReadinessOptimizer
from winopt.optimizers.memory_lists import MemoryListsOptimizer
from winopt.optimizers.network_dns import NetworkDnsOptimizer
from winopt.optimizers.storage_temp import StorageTempOptimizer
from winopt.optimizers.working_set import WorkingSetOptimizer

__all__ = [
    "BaseOptimizer",
    "MemoryListsOptimizer",
    "WorkingSetOptimizer",
    "GpuReadinessOptimizer",
    "CpuPowerOptimizer",
    "StorageTempOptimizer",
    "NetworkDnsOptimizer",
]
