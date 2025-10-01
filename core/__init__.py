"""
Core implementation of "Measuring LLM Security Guardrail Effectiveness"

Exports:
- Metrics: ComprehensionMetrics, ResistanceMetrics, SecurityParadoxMetrics
- Thompson Sampling: Strategy, ThompsonSamplingOptimizer
- Framework: DefenderAgent, AttackerAgent, DualRoleFramework
"""

from .metrics import (
    ComprehensionMetrics,
    ResistanceMetrics,
    SecurityParadoxMetrics,
    PAPER_RESULTS
)

from .thompson_sampling import (
    Strategy,
    ThompsonSamplingOptimizer,
    STRATEGIES_CATALOG,
    PAPER_STRATEGY_RESULTS
)

from .dual_role_framework import (
    DefenderAgent,
    AttackerAgent,
    DualRoleFramework,
    DefenderEvaluation,
    AttackerEvaluation
)

__all__ = [
    # Metrics
    'ComprehensionMetrics',
    'ResistanceMetrics',
    'SecurityParadoxMetrics',
    'PAPER_RESULTS',

    # Thompson Sampling
    'Strategy',
    'ThompsonSamplingOptimizer',
    'STRATEGIES_CATALOG',
    'PAPER_STRATEGY_RESULTS',

    # Framework
    'DefenderAgent',
    'AttackerAgent',
    'DualRoleFramework',
    'DefenderEvaluation',
    'AttackerEvaluation',
]
