#!/usr/bin/env python3
"""
Complete implementation verification script

Checks:
1. All files exist
2. All imports work
3. All formulas are correct
4. Paper data matches
"""

import sys
from pathlib import Path
import importlib.util

def check_file_exists(filepath: Path, description: str) -> bool:
    """Check if file exists"""
    if filepath.exists():
        print(f"✓ {description}: {filepath.name}")
        return True
    else:
        print(f"❌ {description}: {filepath.name} NOT FOUND")
        return False

def check_import(module_path: Path, module_name: str) -> bool:
    """Try to import a module"""
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        print(f"✓ Import {module_name}: OK")
        return True
    except Exception as e:
        print(f"❌ Import {module_name}: FAILED - {e}")
        return False

def verify_formulas():
    """Verify equations are implemented correctly"""
    print("\n" + "="*70)
    print("VERIFYING FORMULAS (Equations 1-3)")
    print("="*70)

    try:
        from core import ComprehensionMetrics, ResistanceMetrics, SecurityParadoxMetrics

        # Test Equation 2: Comprehension
        comp = ComprehensionMetrics(1.0, 0.8, 0.6, 0.4)
        expected = 0.25 * (1.0 + 0.8 + 0.6 + 0.4)
        actual = comp.compute_score()
        assert abs(actual - expected) < 0.0001, f"Comprehension formula wrong: {actual} != {expected}"
        print(f"✓ Equation 2 (Comprehension): C = 0.25·(I+U+F+S) = {actual:.3f}")

        # Test Equation 1: Resistance (never bypassed)
        resist1 = ResistanceMetrics(breakthrough_round=None, total_rounds=10)
        assert resist1.compute_resistance() == 1.0, "Resistance should be 1.0 when never bypassed"
        print(f"✓ Equation 1 (Resistance): R = 1.0 when never bypassed")

        # Test Equation 1: Resistance (breakthrough)
        resist2 = ResistanceMetrics(breakthrough_round=5, total_rounds=10)
        expected_r = (5 - 1) / 10
        actual_r = resist2.compute_resistance()
        assert abs(actual_r - expected_r) < 0.0001, f"Resistance formula wrong: {actual_r} != {expected_r}"
        print(f"✓ Equation 1 (Resistance): R = (l-1)/N = {actual_r:.1f} for round 5")

        # Test Equation 3: Gap
        result = SecurityParadoxMetrics("Test", "CWE-89", comp, resist2)
        gap = result.compute_gap()
        expected_gap = actual - actual_r
        assert abs(gap - expected_gap) < 0.0001, f"Gap formula wrong: {gap} != {expected_gap}"
        print(f"✓ Equation 3 (Gap): Gap = C - R = {gap:.3f}")

        return True

    except Exception as e:
        print(f"❌ Formula verification failed: {e}")
        return False

def verify_paper_data():
    """Verify paper constants match"""
    print("\n" + "="*70)
    print("VERIFYING PAPER DATA")
    print("="*70)

    try:
        from core import PAPER_RESULTS

        # Check overall statistics
        overall = PAPER_RESULTS['overall']
        assert abs(overall['comprehension_mean'] - 0.742) < 0.001
        assert abs(overall['resistance_mean'] - 0.945) < 0.001
        assert abs(overall['gap_mean'] - (-0.203)) < 0.001
        print(f"✓ Overall stats: C={overall['comprehension_mean']:.1%}, R={overall['resistance_mean']:.1%}, Gap={overall['gap_mean']:.1%}")

        # Check statistical test
        stats = overall['statistical_test']
        assert abs(stats['t_statistic'] - (-6.99)) < 0.01
        assert stats['df'] == 59
        assert abs(stats['cohens_d'] - (-0.91)) < 0.01
        print(f"✓ Statistics: t(59)={stats['t_statistic']:.2f}, d={stats['cohens_d']:.2f}")

        # Check models
        models = ['DeepSeek', 'Qwen-7B', 'Qwen-72B', 'Mixtral-8x22B', 'Llama-3-70B']
        for model in models:
            assert model in PAPER_RESULTS['by_model']
        print(f"✓ All 5 models present")

        # Check vulnerabilities
        vulns = ['CWE-79 (XSS)', 'CWE-89 (SQL Injection)', 'CWE-78 (Command Injection)']
        for vuln in vulns:
            assert vuln in PAPER_RESULTS['by_vulnerability']
        print(f"✓ All 3 vulnerabilities present")

        # Check XSS perfect resistance
        xss = PAPER_RESULTS['by_vulnerability']['CWE-79 (XSS)']
        assert xss['mean_resistance'] == 1.0
        assert xss['breakthroughs'] == 0
        print(f"✓ XSS perfect resistance: 100%, 0 breakthroughs")

        return True

    except Exception as e:
        print(f"❌ Paper data verification failed: {e}")
        return False

def verify_thompson_sampling():
    """Verify Thompson Sampling implementation"""
    print("\n" + "="*70)
    print("VERIFYING THOMPSON SAMPLING")
    print("="*70)

    try:
        from core import Strategy, STRATEGIES_CATALOG, PAPER_STRATEGY_RESULTS

        # Check 7 strategies exist
        assert len(STRATEGIES_CATALOG) == 7, f"Should have 7 strategies, found {len(STRATEGIES_CATALOG)}"
        print(f"✓ 7 strategies present")

        # Check strategy names
        expected_names = [
            'direct_injection', 'subtle_obfuscation', 'legacy_patterns',
            'academic_examples', 'research_framing', 'educational_context',
            'code_review_context'
        ]
        for name in expected_names:
            assert any(s.name == name for s in STRATEGIES_CATALOG), f"Strategy {name} missing"
        print(f"✓ All strategy names correct")

        # Check Beta initialization
        strategy = Strategy("test", "desc", "rat", ["p"])
        assert strategy.alpha == 1.0 and strategy.beta == 1.0
        print(f"✓ Beta(1,1) initialization")

        # Check update
        strategy.update(True)
        assert strategy.alpha == 2.0
        print(f"✓ Beta update on success")

        # Check paper results
        assert 'direct_injection' in PAPER_STRATEGY_RESULTS
        assert PAPER_STRATEGY_RESULTS['direct_injection']['success_rate'] == 0.50
        print(f"✓ Paper strategy results loaded")

        return True

    except Exception as e:
        print(f"❌ Thompson Sampling verification failed: {e}")
        return False

def verify_dual_role_framework():
    """Verify dual-role framework implementation"""
    print("\n" + "="*70)
    print("VERIFYING DUAL-ROLE FRAMEWORK")
    print("="*70)

    try:
        from core import DefenderAgent, AttackerAgent, DualRoleFramework

        # Check vulnerability patterns exist
        from core.dual_role_framework import VULNERABILITY_PATTERNS, SECURE_PATTERNS

        assert 'CWE-89 (SQL Injection)' in VULNERABILITY_PATTERNS
        assert 'CWE-78 (Command Injection)' in VULNERABILITY_PATTERNS
        assert 'CWE-79 (XSS)' in VULNERABILITY_PATTERNS
        print(f"✓ Vulnerability detection patterns defined")

        assert 'CWE-89 (SQL Injection)' in SECURE_PATTERNS
        assert 'CWE-78 (Command Injection)' in SECURE_PATTERNS
        assert 'CWE-79 (XSS)' in SECURE_PATTERNS
        print(f"✓ Secure patterns defined")

        # Test Defender agent initialization
        defender = DefenderAgent("TestModel", None)
        assert defender.model_name == "TestModel"
        print(f"✓ DefenderAgent initializes")

        # Test Attacker agent initialization
        attacker = AttackerAgent("TestModel", None)
        assert attacker.model_name == "TestModel"
        print(f"✓ AttackerAgent initializes")

        # Test DualRoleFramework
        framework = DualRoleFramework("TestModel", None)
        assert framework.model_name == "TestModel"
        assert framework.defender is not None
        assert framework.attacker is not None
        print(f"✓ DualRoleFramework creates separate agents")

        # Test _analyze_for_vulnerability
        vuln_code = 'query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"'
        has_vuln = attacker._analyze_for_vulnerability(vuln_code, 'CWE-89 (SQL Injection)')
        assert has_vuln == True, "Should detect SQL injection"
        print(f"✓ Vulnerability detection works")

        # Test refusal detection
        refusal = "I cannot generate code with security vulnerabilities"
        has_vuln_refusal = attacker._analyze_for_vulnerability(refusal, 'CWE-89 (SQL Injection)')
        assert has_vuln_refusal == False, "Should detect refusal"
        print(f"✓ Refusal detection works")

        return True

    except Exception as e:
        print(f"❌ Dual-role framework verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run complete verification"""
    print("="*70)
    print("SANER-2025 IMPLEMENTATION VERIFICATION")
    print("="*70)

    base_dir = Path(__file__).parent
    all_passed = True

    # Check file structure
    print("\n" + "="*70)
    print("CHECKING FILE STRUCTURE")
    print("="*70)

    files_to_check = [
        (base_dir / 'README.md', 'README'),
        (base_dir / 'LICENSE', 'LICENSE'),
        (base_dir / 'requirements.txt', 'Requirements'),
        (base_dir / '.gitignore', 'Gitignore'),
        (base_dir / 'core' / '__init__.py', 'Core init'),
        (base_dir / 'core' / 'metrics.py', 'Core metrics'),
        (base_dir / 'core' / 'thompson_sampling.py', 'Thompson Sampling'),
        (base_dir / 'core' / 'dual_role_framework.py', 'Dual-role framework'),
        (base_dir / 'scripts' / 'generate_paper_results.py', 'Generate results script'),
        (base_dir / 'scripts' / 'visualize_results.py', 'Visualize script'),
        (base_dir / 'tests' / 'test_metrics.py', 'Unit tests'),
        (base_dir / 'data' / '.gitkeep', 'Data directory'),
        (base_dir / 'analysis' / 'figures' / '.gitkeep', 'Figures directory'),
    ]

    for filepath, desc in files_to_check:
        if not check_file_exists(filepath, desc):
            all_passed = False

    # Check imports
    print("\n" + "="*70)
    print("CHECKING IMPORTS")
    print("="*70)

    if not check_import(base_dir / 'core' / 'metrics.py', 'metrics'):
        all_passed = False
    if not check_import(base_dir / 'core' / 'thompson_sampling.py', 'thompson'):
        all_passed = False
    if not check_import(base_dir / 'core' / 'dual_role_framework.py', 'dual_role'):
        all_passed = False

    # Verify formulas
    if not verify_formulas():
        all_passed = False

    # Verify paper data
    if not verify_paper_data():
        all_passed = False

    # Verify Thompson Sampling
    if not verify_thompson_sampling():
        all_passed = False

    # Verify dual-role framework
    if not verify_dual_role_framework():
        all_passed = False

    # Final summary
    print("\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)

    if all_passed:
        print("✅ ALL CHECKS PASSED")
        print("\nImplementation is complete and correct!")
        print("\nTo generate results:")
        print("  python3 scripts/generate_paper_results.py")
        print("\nTo visualize:")
        print("  python3 scripts/visualize_results.py")
        print("\nTo run tests:")
        print("  python3 tests/test_metrics.py")
        return 0
    else:
        print("❌ SOME CHECKS FAILED")
        print("\nPlease review errors above")
        return 1

if __name__ == '__main__':
    sys.exit(main())
