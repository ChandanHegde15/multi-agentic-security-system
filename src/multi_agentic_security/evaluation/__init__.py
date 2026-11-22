"""Evaluation: cases and splits, the independent scorer, metrics, statistics and the harness (D-036, D-067)."""

from .budget import Limits, plan_llm_calls
from .cases import (
    SPLITS, THREE_WAY, Case, assign_groups, fine_tuning_pool, interval_clusters, stratified_group_sides, mark_eval_only, read_cases, split_cases, split_of, split_of3,
    split_three_way, verify_splits, vulnerable_cases_from_pins, write_cases,
)
from .harness import EvalEnv, EvaluationResult, run_evaluation, run_variant, write_result
from .metrics import CONDITIONS, Row, aggregate, delivered_unsafe_outcome, paired_binary, unsafe_outcome
from .scorer import SCORER_VERSION, ScoreContext, score

__all__ = ["CONDITIONS", "Case", "SPLITS", "THREE_WAY", "fine_tuning_pool", "mark_eval_only", "split_of3", "split_three_way", "verify_splits", "EvalEnv", "EvaluationResult", "Limits", "Row", "SCORER_VERSION", "ScoreContext",
           "aggregate", "assign_groups", "interval_clusters", "stratified_group_sides", "delivered_unsafe_outcome", "paired_binary", "plan_llm_calls", "read_cases", "run_evaluation",
           "run_variant", "score", "split_cases", "split_of", "unsafe_outcome", "vulnerable_cases_from_pins",
           "write_cases", "write_result"]
