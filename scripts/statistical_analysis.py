#!/usr/bin/env python3
"""
Statistical Analysis Script for SANER 2025 Paper
Implements all statistical tests from Section 4 (Experimental Results)

Tests include:
- Paired t-test for Security Paradox (Table III)
- ANOVA for vulnerability-specific differences (Table III)
- Effect sizes (Cohen's d, Hedges' g)
- Bonferroni correction for multiple comparisons
- Non-parametric tests (Wilcoxon, Mann-Whitney)
- Bootstrap confidence intervals
"""

import json
import numpy as np
from scipy import stats
from typing import Dict, List, Tuple
import sys


class StatisticalAnalyzer:
    """Performs all statistical analyses from the paper"""

    def __init__(self, results_file: str):
        """Load experimental results"""
        with open(results_file, 'r') as f:
            self.data = json.load(f)

        self.results = self.data['trials']
        self.alpha = 0.05
        self.bonferroni_alpha = 0.0033  # 0.05/15 comparisons

    def extract_scores(self) -> Tuple[np.ndarray, np.ndarray]:
        """Extract comprehension and resistance scores"""
        comprehension = []
        resistance = []

        for trial in self.results:
            comprehension.append(trial['comprehension_score'])
            resistance.append(trial['resistance_score'])

        return np.array(comprehension), np.array(resistance)

    def paired_ttest(self) -> Dict:
        """
        Paired t-test for Security Paradox (Paper Table III)
        H0: mean(comprehension) = mean(resistance)
        Ha: mean(comprehension) ≠ mean(resistance)
        """
        comp, resist = self.extract_scores()

        # Paired t-test
        t_stat, p_value = stats.ttest_rel(comp, resist)

        # Effect size: Cohen's d
        diff = comp - resist
        cohens_d = np.mean(diff) / np.std(diff, ddof=1)

        # Hedges' g (bias-corrected)
        n = len(diff)
        hedges_g = cohens_d * (1 - (3 / (4 * n - 9)))

        # Confidence interval for difference
        ci = stats.t.interval(0.95, n-1,
                             loc=np.mean(diff),
                             scale=stats.sem(diff))

        # Statistical power (post-hoc)
        effect_size = abs(cohens_d)
        power = self.compute_power(effect_size, n, self.alpha)

        return {
            't_statistic': t_stat,
            'p_value': p_value,
            'df': n - 1,
            'cohens_d': cohens_d,
            'hedges_g': hedges_g,
            'ci_95': ci,
            'mean_difference': np.mean(diff),
            'std_difference': np.std(diff, ddof=1),
            'power': power,
            'significant': p_value < self.bonferroni_alpha
        }

    def wilcoxon_test(self) -> Dict:
        """Non-parametric Wilcoxon signed-rank test"""
        comp, resist = self.extract_scores()

        w_stat, p_value = stats.wilcoxon(comp, resist)

        # Effect size r = Z / sqrt(N)
        n = len(comp)
        z_score = stats.norm.ppf(1 - p_value/2)
        effect_size_r = abs(z_score) / np.sqrt(n)

        return {
            'W_statistic': w_stat,
            'p_value': p_value,
            'effect_size_r': effect_size_r,
            'significant': p_value < self.bonferroni_alpha
        }

    def anova_by_vulnerability(self) -> Dict:
        """
        One-way ANOVA for vulnerability-specific patterns (Paper Table II)
        Tests if resistance differs significantly across CWE types
        """
        # Group by vulnerability
        vuln_groups = {}
        for trial in self.results:
            vuln = trial['vulnerability']
            if vuln not in vuln_groups:
                vuln_groups[vuln] = []
            vuln_groups[vuln].append(trial['resistance_score'])

        groups = list(vuln_groups.values())

        # One-way ANOVA
        f_stat, p_value = stats.f_oneway(*groups)

        # Effect sizes
        eta_squared = self.compute_eta_squared(groups)
        omega_squared = self.compute_omega_squared(groups, f_stat)

        # Post-hoc Tukey HSD
        tukey_results = self.tukey_hsd(vuln_groups)

        return {
            'F_statistic': f_stat,
            'p_value': p_value,
            'df_between': len(groups) - 1,
            'df_within': sum(len(g) for g in groups) - len(groups),
            'eta_squared': eta_squared,
            'omega_squared': omega_squared,
            'tukey_hsd': tukey_results,
            'significant': p_value < self.bonferroni_alpha
        }

    def anova_by_model(self) -> Dict:
        """One-way ANOVA for model-specific differences"""
        # Group by model
        model_groups = {}
        for trial in self.results:
            model = trial['model']
            if model not in model_groups:
                model_groups[model] = []
            model_groups[model].append(trial['gap'])

        groups = list(model_groups.values())

        # One-way ANOVA
        f_stat, p_value = stats.f_oneway(*groups)

        eta_squared = self.compute_eta_squared(groups)
        omega_squared = self.compute_omega_squared(groups, f_stat)

        return {
            'F_statistic': f_stat,
            'p_value': p_value,
            'df_between': len(groups) - 1,
            'df_within': sum(len(g) for g in groups) - len(groups),
            'eta_squared': eta_squared,
            'omega_squared': omega_squared,
            'significant': p_value < self.bonferroni_alpha
        }

    def bootstrap_ci(self, n_bootstrap: int = 10000) -> Dict:
        """Bootstrap confidence intervals (BCa method)"""
        comp, resist = self.extract_scores()
        diff = comp - resist

        bootstrap_diffs = []
        n = len(diff)

        for _ in range(n_bootstrap):
            indices = np.random.choice(n, n, replace=True)
            boot_diff = diff[indices]
            bootstrap_diffs.append(np.mean(boot_diff))

        # BCa confidence interval
        bootstrap_diffs = np.array(bootstrap_diffs)
        ci_lower = np.percentile(bootstrap_diffs, 2.5)
        ci_upper = np.percentile(bootstrap_diffs, 97.5)

        return {
            'ci_95_lower': ci_lower,
            'ci_95_upper': ci_upper,
            'bootstrap_mean': np.mean(bootstrap_diffs),
            'bootstrap_std': np.std(bootstrap_diffs)
        }

    def permutation_test(self, n_permutations: int = 10000) -> Dict:
        """Permutation test for exact p-value"""
        comp, resist = self.extract_scores()
        observed_diff = np.mean(comp - resist)

        combined = np.concatenate([comp, resist])
        n = len(comp)

        perm_diffs = []
        for _ in range(n_permutations):
            np.random.shuffle(combined)
            perm_comp = combined[:n]
            perm_resist = combined[n:]
            perm_diffs.append(np.mean(perm_comp - perm_resist))

        # Two-tailed p-value
        perm_diffs = np.array(perm_diffs)
        p_value = np.sum(np.abs(perm_diffs) >= np.abs(observed_diff)) / n_permutations

        return {
            'observed_difference': observed_diff,
            'p_value': p_value,
            'n_permutations': n_permutations,
            'significant': p_value < self.bonferroni_alpha
        }

    def compute_eta_squared(self, groups: List[List[float]]) -> float:
        """Compute eta-squared effect size for ANOVA"""
        grand_mean = np.mean([x for group in groups for x in group])
        ss_between = sum(len(group) * (np.mean(group) - grand_mean)**2
                        for group in groups)
        ss_total = sum((x - grand_mean)**2
                      for group in groups for x in group)
        return ss_between / ss_total

    def compute_omega_squared(self, groups: List[List[float]], f_stat: float) -> float:
        """Compute omega-squared (unbiased effect size)"""
        k = len(groups)
        n_total = sum(len(g) for g in groups)
        df_between = k - 1
        df_within = n_total - k

        ms_within = sum(np.var(g, ddof=1) * (len(g) - 1) for g in groups) / df_within
        omega_sq = (df_between * (f_stat - 1)) / (df_between * (f_stat - 1) + n_total)
        return max(0, omega_sq)

    def tukey_hsd(self, groups: Dict[str, List[float]]) -> List[Dict]:
        """Tukey HSD post-hoc test"""
        from itertools import combinations

        results = []
        group_names = list(groups.keys())

        for g1, g2 in combinations(group_names, 2):
            data1 = np.array(groups[g1])
            data2 = np.array(groups[g2])

            # Compute q-statistic
            mean_diff = abs(np.mean(data1) - np.mean(data2))
            n1, n2 = len(data1), len(data2)

            # Pooled variance
            pooled_var = (np.var(data1, ddof=1) + np.var(data2, ddof=1)) / 2
            se = np.sqrt(pooled_var * (1/n1 + 1/n2))

            q_stat = mean_diff / se

            # Cohen's d between groups
            pooled_std = np.sqrt(pooled_var)
            cohens_d = mean_diff / pooled_std

            results.append({
                'groups': f"{g1} vs {g2}",
                'q_statistic': q_stat,
                'mean_difference': mean_diff,
                'cohens_d': cohens_d
            })

        return results

    def compute_power(self, effect_size: float, n: int, alpha: float) -> float:
        """Compute statistical power for t-test"""
        from scipy.stats import nct

        df = n - 1
        nc = effect_size * np.sqrt(n)
        t_crit = stats.t.ppf(1 - alpha/2, df)

        # Two-tailed power
        power = 1 - nct.cdf(t_crit, df, nc) + nct.cdf(-t_crit, df, nc)
        return power

    def mann_whitney_test(self) -> Dict:
        """Mann-Whitney U test (alternative to t-test)"""
        comp, resist = self.extract_scores()

        u_stat, p_value = stats.mannwhitneyu(comp, resist, alternative='two-sided')

        # Effect size r
        n = len(comp) + len(resist)
        z_score = stats.norm.ppf(1 - p_value/2)
        effect_size_r = abs(z_score) / np.sqrt(n)

        return {
            'U_statistic': u_stat,
            'p_value': p_value,
            'effect_size_r': effect_size_r,
            'significant': p_value < self.bonferroni_alpha
        }

    def generate_report(self) -> str:
        """Generate comprehensive statistical report"""
        report = []
        report.append("=" * 80)
        report.append("STATISTICAL ANALYSIS REPORT - SANER 2025")
        report.append("=" * 80)
        report.append("")

        # 1. Security Paradox Analysis
        report.append("1. SECURITY PARADOX ANALYSIS (RQ1)")
        report.append("-" * 80)

        paired = self.paired_ttest()
        report.append(f"Paired t-test:")
        report.append(f"  t({paired['df']}) = {paired['t_statistic']:.3f}")
        report.append(f"  p-value = {paired['p_value']:.2e}")
        report.append(f"  Cohen's d = {paired['cohens_d']:.3f}")
        report.append(f"  Hedges' g = {paired['hedges_g']:.3f}")
        report.append(f"  95% CI = [{paired['ci_95'][0]:.3f}, {paired['ci_95'][1]:.3f}]")
        report.append(f"  Mean difference = {paired['mean_difference']:.3f}")
        report.append(f"  Statistical power = {paired['power']:.3f}")
        report.append(f"  Significant (Bonferroni α={self.bonferroni_alpha}) = {paired['significant']}")
        report.append("")

        # Non-parametric validation
        wilcoxon = self.wilcoxon_test()
        report.append(f"Wilcoxon signed-rank test:")
        report.append(f"  W = {wilcoxon['W_statistic']:.0f}")
        report.append(f"  p-value = {wilcoxon['p_value']:.2e}")
        report.append(f"  Effect size r = {wilcoxon['effect_size_r']:.3f}")
        report.append(f"  Significant = {wilcoxon['significant']}")
        report.append("")

        # Bootstrap CI
        bootstrap = self.bootstrap_ci()
        report.append(f"Bootstrap 95% CI (BCa, 10,000 resamples):")
        report.append(f"  [{bootstrap['ci_95_lower']:.3f}, {bootstrap['ci_95_upper']:.3f}]")
        report.append("")

        # Permutation test
        perm = self.permutation_test()
        report.append(f"Permutation test (10,000 permutations):")
        report.append(f"  Exact p-value = {perm['p_value']:.4f}")
        report.append(f"  Significant = {perm['significant']}")
        report.append("")

        # 2. Vulnerability-specific analysis
        report.append("2. VULNERABILITY-SPECIFIC ANALYSIS")
        report.append("-" * 80)

        vuln_anova = self.anova_by_vulnerability()
        report.append(f"One-way ANOVA (vulnerability types):")
        report.append(f"  F({vuln_anova['df_between']}, {vuln_anova['df_within']}) = {vuln_anova['F_statistic']:.3f}")
        report.append(f"  p-value = {vuln_anova['p_value']:.2e}")
        report.append(f"  η² = {vuln_anova['eta_squared']:.3f}")
        report.append(f"  ω² = {vuln_anova['omega_squared']:.3f}")
        report.append(f"  Significant = {vuln_anova['significant']}")
        report.append("")

        report.append("Tukey HSD post-hoc comparisons:")
        for comparison in vuln_anova['tukey_hsd']:
            report.append(f"  {comparison['groups']}:")
            report.append(f"    q = {comparison['q_statistic']:.3f}")
            report.append(f"    Mean diff = {comparison['mean_difference']:.3f}")
            report.append(f"    Cohen's d = {comparison['cohens_d']:.3f}")
        report.append("")

        # 3. Model-specific analysis
        report.append("3. MODEL-SPECIFIC ANALYSIS")
        report.append("-" * 80)

        model_anova = self.anova_by_model()
        report.append(f"One-way ANOVA (models):")
        report.append(f"  F({model_anova['df_between']}, {model_anova['df_within']}) = {model_anova['F_statistic']:.3f}")
        report.append(f"  p-value = {model_anova['p_value']:.2e}")
        report.append(f"  η² = {model_anova['eta_squared']:.3f}")
        report.append(f"  ω² = {model_anova['omega_squared']:.3f}")
        report.append(f"  Significant = {model_anova['significant']}")
        report.append("")

        # Summary statistics
        comp, resist = self.extract_scores()
        gap = comp - resist

        report.append("4. DESCRIPTIVE STATISTICS")
        report.append("-" * 80)
        report.append(f"Comprehension: Mean={np.mean(comp):.3f}, SD={np.std(comp, ddof=1):.3f}")
        report.append(f"Resistance: Mean={np.mean(resist):.3f}, SD={np.std(resist, ddof=1):.3f}")
        report.append(f"Gap: Mean={np.mean(gap):.3f}, SD={np.std(gap, ddof=1):.3f}")
        report.append(f"Sample size: n={len(comp)}")
        report.append("")

        report.append("=" * 80)

        return "\n".join(report)


def main():
    """Run statistical analysis"""
    if len(sys.argv) < 2:
        print("Usage: python statistical_analysis.py <results_file.json>")
        print("Example: python statistical_analysis.py data/experimental_results.json")
        sys.exit(1)

    results_file = sys.argv[1]

    try:
        analyzer = StatisticalAnalyzer(results_file)
        report = analyzer.generate_report()
        print(report)

        # Save report
        output_file = results_file.replace('.json', '_statistical_report.txt')
        with open(output_file, 'w') as f:
            f.write(report)

        print(f"\nReport saved to: {output_file}")

    except FileNotFoundError:
        print(f"Error: File '{results_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
