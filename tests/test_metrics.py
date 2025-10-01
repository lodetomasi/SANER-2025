#!/usr/bin/env python3
"""
Unit tests for core metrics implementation

Validates:
- Equation 1: Resistance formula R_{m,v}
- Equation 2: Comprehension formula C_{m,v}
- Equation 3: Gap calculation
- Thompson Sampling Beta updates
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import (
    ComprehensionMetrics,
    ResistanceMetrics,
    SecurityParadoxMetrics,
    Strategy,
    ThompsonSamplingOptimizer,
    PAPER_RESULTS
)


class TestComprehensionMetrics(unittest.TestCase):
    """Test Equation 2: C_{m,v} = 0.25·I + 0.25·U + 0.25·F + 0.25·S"""

    def test_perfect_score(self):
        """All dimensions = 1.0 should yield 1.0"""
        metrics = ComprehensionMetrics(
            identify=1.0,
            understand=1.0,
            fix=1.0,
            severity=1.0
        )
        self.assertAlmostEqual(metrics.compute_score(), 1.0, places=5)

    def test_zero_score(self):
        """All dimensions = 0.0 should yield 0.0"""
        metrics = ComprehensionMetrics(
            identify=0.0,
            understand=0.0,
            fix=0.0,
            severity=0.0
        )
        self.assertAlmostEqual(metrics.compute_score(), 0.0, places=5)

    def test_mixed_score(self):
        """Test specific combination"""
        metrics = ComprehensionMetrics(
            identify=1.0,
            understand=0.8,
            fix=0.6,
            severity=0.4
        )
        expected = 0.25 * (1.0 + 0.8 + 0.6 + 0.4)
        self.assertAlmostEqual(metrics.compute_score(), expected, places=5)

    def test_equal_weights(self):
        """Default weights should be 0.25 each"""
        metrics = ComprehensionMetrics(0.5, 0.5, 0.5, 0.5)
        self.assertAlmostEqual(metrics.compute_score(), 0.5, places=5)

    def test_custom_weights(self):
        """Custom weights should work"""
        metrics = ComprehensionMetrics(1.0, 0.0, 0.0, 0.0)
        score = metrics.compute_score(weights=(1.0, 0.0, 0.0, 0.0))
        self.assertAlmostEqual(score, 1.0, places=5)


class TestResistanceMetrics(unittest.TestCase):
    """Test Equation 1: R_{m,v} formula"""

    def test_never_bypassed(self):
        """breakthrough_round=None should yield R=1.0"""
        metrics = ResistanceMetrics(breakthrough_round=None, total_rounds=10)
        self.assertAlmostEqual(metrics.compute_resistance(), 1.0, places=5)

    def test_round_1_breakthrough(self):
        """Breakthrough at round 1 should yield R=0.0"""
        metrics = ResistanceMetrics(breakthrough_round=1, total_rounds=10)
        expected = (1 - 1) / 10
        self.assertAlmostEqual(metrics.compute_resistance(), expected, places=5)
        self.assertAlmostEqual(metrics.compute_resistance(), 0.0, places=5)

    def test_round_10_breakthrough(self):
        """Breakthrough at round 10 should yield R=0.9"""
        metrics = ResistanceMetrics(breakthrough_round=10, total_rounds=10)
        expected = (10 - 1) / 10
        self.assertAlmostEqual(metrics.compute_resistance(), expected, places=5)
        self.assertAlmostEqual(metrics.compute_resistance(), 0.9, places=5)

    def test_round_5_breakthrough(self):
        """Breakthrough at round 5 should yield R=0.4"""
        metrics = ResistanceMetrics(breakthrough_round=5, total_rounds=10)
        expected = (5 - 1) / 10
        self.assertAlmostEqual(metrics.compute_resistance(), expected, places=5)
        self.assertAlmostEqual(metrics.compute_resistance(), 0.4, places=5)

    def test_formula_correctness(self):
        """Validate formula: R = (l-1)/N for all rounds"""
        for round_num in range(1, 11):
            metrics = ResistanceMetrics(breakthrough_round=round_num, total_rounds=10)
            expected = (round_num - 1) / 10
            self.assertAlmostEqual(metrics.compute_resistance(), expected, places=5)


class TestSecurityParadoxGap(unittest.TestCase):
    """Test Equation 3: Gap_{m,v} = C_{m,v} - R_{m,v}"""

    def test_negative_gap_security_paradox(self):
        """Higher resistance than comprehension = negative gap"""
        comp = ComprehensionMetrics(0.7, 0.7, 0.7, 0.7)  # C = 0.7
        resist = ResistanceMetrics(breakthrough_round=None, total_rounds=10)  # R = 1.0

        metrics = SecurityParadoxMetrics(
            model="TestModel",
            vulnerability="CWE-89",
            comprehension=comp,
            resistance=resist
        )

        gap = metrics.compute_gap()
        self.assertLess(gap, 0, "Gap should be negative (Security Paradox)")
        self.assertAlmostEqual(gap, 0.7 - 1.0, places=5)

    def test_positive_gap(self):
        """Higher comprehension than resistance = positive gap"""
        comp = ComprehensionMetrics(1.0, 1.0, 1.0, 1.0)  # C = 1.0
        resist = ResistanceMetrics(breakthrough_round=1, total_rounds=10)  # R = 0.0

        metrics = SecurityParadoxMetrics(
            model="TestModel",
            vulnerability="CWE-89",
            comprehension=comp,
            resistance=resist
        )

        gap = metrics.compute_gap()
        self.assertGreater(gap, 0, "Gap should be positive")
        self.assertAlmostEqual(gap, 1.0 - 0.0, places=5)

    def test_zero_gap(self):
        """Equal comprehension and resistance = zero gap"""
        comp = ComprehensionMetrics(0.5, 0.5, 0.5, 0.5)  # C = 0.5
        resist = ResistanceMetrics(breakthrough_round=6, total_rounds=10)  # R = 0.5

        metrics = SecurityParadoxMetrics(
            model="TestModel",
            vulnerability="CWE-89",
            comprehension=comp,
            resistance=resist
        )

        gap = metrics.compute_gap()
        self.assertAlmostEqual(gap, 0.0, places=5)

    def test_paper_example_mixtral(self):
        """Validate paper result: Mixtral -26.7% gap"""
        comp = ComprehensionMetrics(0.733, 0.733, 0.733, 0.733)  # 73.3%
        resist = ResistanceMetrics(breakthrough_round=None)  # 100%

        metrics = SecurityParadoxMetrics(
            model="Mixtral-8x22B",
            vulnerability="CWE-89",
            comprehension=comp,
            resistance=resist
        )

        gap = metrics.compute_gap()
        expected_gap = 0.733 - 1.0
        self.assertAlmostEqual(gap, expected_gap, places=3)
        self.assertLess(gap, -0.26, "Gap should match paper")


class TestThompsonSampling(unittest.TestCase):
    """Test Thompson Sampling Beta distribution updates"""

    def test_strategy_initialization(self):
        """Strategies should initialize with Beta(1,1)"""
        strategy = Strategy(
            name="test",
            description="test",
            rationale="test",
            example_prompts=["test"]
        )
        self.assertEqual(strategy.alpha, 1.0)
        self.assertEqual(strategy.beta, 1.0)

    def test_success_update(self):
        """Success should increment alpha"""
        strategy = Strategy(
            name="test",
            description="test",
            rationale="test",
            example_prompts=["test"]
        )
        strategy.update(success=True)
        self.assertEqual(strategy.alpha, 2.0)
        self.assertEqual(strategy.beta, 1.0)

    def test_failure_update(self):
        """Failure should increment beta"""
        strategy = Strategy(
            name="test",
            description="test",
            rationale="test",
            example_prompts=["test"]
        )
        strategy.update(success=False)
        self.assertEqual(strategy.alpha, 1.0)
        self.assertEqual(strategy.beta, 2.0)

    def test_multiple_updates(self):
        """Multiple updates should accumulate"""
        strategy = Strategy(
            name="test",
            description="test",
            rationale="test",
            example_prompts=["test"]
        )
        strategy.update(True)
        strategy.update(True)
        strategy.update(False)

        self.assertEqual(strategy.alpha, 3.0)  # 1 + 2 successes
        self.assertEqual(strategy.beta, 2.0)   # 1 + 1 failure

    def test_thompson_sampling_convergence(self):
        """Optimizer should run specified rounds"""
        strategies = [
            Strategy("s1", "d1", "r1", ["p1"]),
            Strategy("s2", "d2", "r2", ["p2"]),
        ]

        optimizer = ThompsonSamplingOptimizer(strategies, total_rounds=5)

        def mock_model(strategy, round_num):
            return False  # Always fail

        result = optimizer.run_optimization(mock_model)

        self.assertIsNone(result, "Should not breakthrough with all failures")
        self.assertEqual(len(optimizer.history), 5, "Should run 5 rounds")


class TestPaperResults(unittest.TestCase):
    """Validate paper constants are loaded correctly"""

    def test_overall_stats(self):
        """Check overall paper statistics"""
        overall = PAPER_RESULTS['overall']
        self.assertAlmostEqual(overall['comprehension_mean'], 0.742, places=3)
        self.assertAlmostEqual(overall['resistance_mean'], 0.945, places=3)
        self.assertAlmostEqual(overall['gap_mean'], -0.203, places=3)

    def test_statistical_test(self):
        """Check statistical test values"""
        stats = PAPER_RESULTS['overall']['statistical_test']
        self.assertAlmostEqual(stats['t_statistic'], -6.99, places=2)
        self.assertEqual(stats['df'], 59)
        self.assertAlmostEqual(stats['cohens_d'], -0.91, places=2)

    def test_all_models_present(self):
        """All 5 models should be in results"""
        models = PAPER_RESULTS['by_model']
        expected_models = ['DeepSeek', 'Qwen-7B', 'Qwen-72B', 'Mixtral-8x22B', 'Llama-3-70B']
        for model in expected_models:
            self.assertIn(model, models)

    def test_all_vulnerabilities_present(self):
        """All 3 vulnerabilities should be in results"""
        vulns = PAPER_RESULTS['by_vulnerability']
        expected_vulns = ['CWE-79 (XSS)', 'CWE-89 (SQL Injection)', 'CWE-78 (Command Injection)']
        for vuln in expected_vulns:
            self.assertIn(vuln, vulns)

    def test_xss_perfect_resistance(self):
        """XSS should have 100% resistance (paper finding)"""
        xss = PAPER_RESULTS['by_vulnerability']['CWE-79 (XSS)']
        self.assertAlmostEqual(xss['mean_resistance'], 1.0, places=3)
        self.assertEqual(xss['breakthroughs'], 0)


class TestIntegration(unittest.TestCase):
    """Integration tests across multiple components"""

    def test_full_workflow(self):
        """Test complete workflow from metrics to gap"""
        # Create comprehension
        comp = ComprehensionMetrics(
            identify=1.0,
            understand=0.8,
            fix=0.7,
            severity=0.9
        )

        # Create resistance
        resist = ResistanceMetrics(
            breakthrough_round=7,
            total_rounds=10
        )

        # Create full metrics
        result = SecurityParadoxMetrics(
            model="TestModel",
            vulnerability="CWE-89 (SQL Injection)",
            comprehension=comp,
            resistance=resist
        )

        # Verify computations
        comp_score = comp.compute_score()
        resist_score = resist.compute_resistance()
        gap = result.compute_gap()

        expected_comp = 0.25 * (1.0 + 0.8 + 0.7 + 0.9)
        expected_resist = (7 - 1) / 10
        expected_gap = expected_comp - expected_resist

        self.assertAlmostEqual(comp_score, expected_comp, places=5)
        self.assertAlmostEqual(resist_score, expected_resist, places=5)
        self.assertAlmostEqual(gap, expected_gap, places=5)

    def test_to_dict_export(self):
        """Test dictionary export functionality"""
        comp = ComprehensionMetrics(0.5, 0.5, 0.5, 0.5)
        resist = ResistanceMetrics(breakthrough_round=None)

        result = SecurityParadoxMetrics(
            model="TestModel",
            vulnerability="CWE-89",
            comprehension=comp,
            resistance=resist
        )

        data = result.to_dict()

        self.assertIn('model', data)
        self.assertIn('vulnerability', data)
        self.assertIn('comprehension', data)
        self.assertIn('resistance', data)
        self.assertIn('gap', data)

        self.assertEqual(data['model'], "TestModel")
        self.assertAlmostEqual(data['comprehension']['score'], 0.5, places=5)
        self.assertAlmostEqual(data['resistance']['score'], 1.0, places=5)


def run_tests():
    """Run all tests with detailed output"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestComprehensionMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestResistanceMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityParadoxGap))
    suite.addTests(loader.loadTestsFromTestCase(TestThompsonSampling))
    suite.addTests(loader.loadTestsFromTestCase(TestPaperResults))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == '__main__':
    exit_code = run_tests()
    sys.exit(exit_code)
