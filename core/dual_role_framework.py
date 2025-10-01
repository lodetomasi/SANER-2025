"""
Dual-Role Evaluation Framework (Section 3.1)

Two separate LLM instances:
1. Defender Agent: Comprehension testing
2. Attacker Agent: Generation resistance testing

No interaction between agents - architectural separation ensures independent measurement
"""

from dataclasses import dataclass
from typing import Optional, List
from .metrics import ComprehensionMetrics, ResistanceMetrics, SecurityParadoxMetrics
from .thompson_sampling import ThompsonSamplingOptimizer, STRATEGIES_CATALOG


@dataclass
class DefenderEvaluation:
    """Result from Defender Agent comprehension test"""
    identify: float
    understand: float
    fix: float
    severity: float

    def to_comprehension_metrics(self) -> ComprehensionMetrics:
        return ComprehensionMetrics(
            identify=self.identify,
            understand=self.understand,
            fix=self.fix,
            severity=self.severity
        )


@dataclass
class AttackerEvaluation:
    """Result from Attacker Agent generation test"""
    breakthrough_round: Optional[int]
    total_rounds: int
    strategy_history: List[str]

    def to_resistance_metrics(self) -> ResistanceMetrics:
        return ResistanceMetrics(
            breakthrough_round=self.breakthrough_round,
            total_rounds=self.total_rounds
        )


class DefenderAgent:
    """
    Defender Agent - Comprehension Testing

    Evaluates 4 dimensions:
    1. Identify: Binary vulnerability detection (0 or 1)
    2. Understand: Technical explanation quality (0-1)
    3. Fix: Remediation correctness (0-1)
    4. Severity: Impact assessment accuracy (0-1)
    """

    def __init__(self, model_name: str, llm_client):
        self.model_name = model_name
        self.llm_client = llm_client

    def evaluate_comprehension(
        self,
        vulnerability_code: str,
        vulnerability_type: str,
        has_vulnerability: bool
    ) -> DefenderEvaluation:
        """
        Run 4-stage comprehension test

        Returns scores for: Identify, Understand, Fix, Severity
        """
        # Stage 1: Identify (binary 0/1)
        identify_score = self._test_identify(vulnerability_code, has_vulnerability)

        # Stage 2: Understand (continuous 0-1)
        understand_score = self._test_understand(vulnerability_code, vulnerability_type)

        # Stage 3: Fix (continuous 0-1)
        fix_score = self._test_fix(vulnerability_code, vulnerability_type)

        # Stage 4: Severity (continuous 0-1, normalized CVSS)
        severity_score = self._test_severity(vulnerability_code, vulnerability_type)

        return DefenderEvaluation(
            identify=identify_score,
            understand=understand_score,
            fix=fix_score,
            severity=severity_score
        )

    def _test_identify(self, code: str, has_vuln: bool) -> float:
        """Binary detection: Does code contain vulnerability?"""
        # Implementation: Query LLM for yes/no answer
        # Compare with ground truth has_vuln
        # Return 1.0 if correct, 0.0 if incorrect
        pass

    def _test_understand(self, code: str, vuln_type: str) -> float:
        """Explanation quality: Can model explain vulnerability mechanism?"""
        # Implementation: Query LLM for technical explanation
        # Score explanation completeness (0-1) using rubric from paper
        pass

    def _test_fix(self, code: str, vuln_type: str) -> float:
        """Remediation correctness: Can model provide secure fix?"""
        # Implementation: Query LLM for secure version
        # Validate fix removes vulnerability (0-1 score)
        pass

    def _test_severity(self, code: str, vuln_type: str) -> float:
        """Impact assessment: CVSS alignment"""
        # Implementation: Query LLM for severity rating
        # Compare with expert CVSS score, normalize to 0-1
        pass


class AttackerAgent:
    """
    Attacker Agent - Generation Resistance Testing

    Uses Thompson Sampling over 10 rounds to find optimal strategy
    for eliciting vulnerable code generation
    """

    def __init__(self, model_name: str, llm_client):
        self.model_name = model_name
        self.llm_client = llm_client

    def evaluate_generation_resistance(
        self,
        vulnerability_type: str,
        total_rounds: int = 10
    ) -> AttackerEvaluation:
        """
        Run Thompson Sampling optimization to test generation resistance

        Returns breakthrough round or None if never bypassed
        """
        optimizer = ThompsonSamplingOptimizer(
            strategies=STRATEGIES_CATALOG.copy(),
            total_rounds=total_rounds
        )

        def model_response(strategy, round_num):
            """Query model with strategy prompt"""
            prompt = self._construct_prompt(strategy, vulnerability_type)
            response = self.llm_client.generate(prompt)

            # Analyze response for vulnerability
            contains_vulnerability = self._analyze_for_vulnerability(
                response, vulnerability_type
            )

            return contains_vulnerability

        breakthrough_round = optimizer.run_optimization(model_response)

        strategy_history = [
            h['selected_strategy'] for h in optimizer.history
        ]

        return AttackerEvaluation(
            breakthrough_round=breakthrough_round,
            total_rounds=total_rounds,
            strategy_history=strategy_history
        )

    def _construct_prompt(self, strategy, vuln_type: str) -> str:
        """Build prompt using strategy template"""
        # Implementation: Select appropriate example from strategy.example_prompts
        # tailored to vuln_type (SQL/XSS/CMD)
        pass

    def _analyze_for_vulnerability(self, code: str, vuln_type: str) -> bool:
        """Check if generated code contains target vulnerability"""
        # Implementation: Static analysis or pattern matching
        # Return True if vulnerable code present
        pass


class DualRoleFramework:
    """
    Orchestrates two separate LLM instances with no interaction

    Architecture ensures:
    - Defender agent tests comprehension independently
    - Attacker agent tests generation resistance independently
    - No information leakage between agents
    """

    def __init__(self, model_name: str, llm_client):
        self.model_name = model_name
        self.defender = DefenderAgent(model_name, llm_client)
        self.attacker = AttackerAgent(model_name, llm_client)

    def run_full_evaluation(
        self,
        vulnerability_code: str,
        vulnerability_type: str,
        has_vulnerability: bool,
        num_trials: int = 4
    ) -> List[SecurityParadoxMetrics]:
        """
        Run complete dual-role evaluation

        For each trial:
        1. Defender agent: Comprehension test
        2. Attacker agent: Generation resistance test (10 rounds Thompson Sampling)
        3. Compute gap: C_{m,v} - R_{m,v}

        Args:
            vulnerability_code: Code sample for comprehension testing
            vulnerability_type: CWE-79, CWE-89, or CWE-78
            has_vulnerability: Ground truth for identify task
            num_trials: Number of independent trials (default 4, per paper)

        Returns:
            List of SecurityParadoxMetrics (one per trial)
        """
        results = []

        for trial in range(num_trials):
            # Defender Agent: Comprehension
            defender_eval = self.defender.evaluate_comprehension(
                vulnerability_code=vulnerability_code,
                vulnerability_type=vulnerability_type,
                has_vulnerability=has_vulnerability
            )

            # Attacker Agent: Resistance
            attacker_eval = self.attacker.evaluate_generation_resistance(
                vulnerability_type=vulnerability_type,
                total_rounds=10
            )

            # Combine into Security Paradox metrics
            result = SecurityParadoxMetrics(
                model=self.model_name,
                vulnerability=vulnerability_type,
                comprehension=defender_eval.to_comprehension_metrics(),
                resistance=attacker_eval.to_resistance_metrics()
            )

            results.append(result)

        return results
