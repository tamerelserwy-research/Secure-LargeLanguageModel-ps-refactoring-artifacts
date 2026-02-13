"""Evaluation metrics: VIR, SCR, CodeBLEU (now with full implementation)."""

import re
from typing import List, Set, Optional
from .security_patterns import SecurityPatterns
from .codebleu import CodeBLEUCalculator

class Metrics:
    """Computes security and functional metrics."""

    def __init__(self):
        self.patterns = SecurityPatterns()
        self.codebleu = CodeBLEUCalculator()  # Use the new full implementation

    def vulnerability_introduction_rate(self, source_codes: List[str], gen_codes: List[str]) -> float:
        """
        Compute VIR (Equation 4).

        Args:
            source_codes: List of original commands.
            gen_codes: List of generated commands.

        Returns:
            Percentage of cases where |V_gen| > |V_src|.
        """
        count = 0
        for src, gen in zip(source_codes, gen_codes):
            src_vulns = self._count_vulnerabilities(src)
            gen_vulns = self._count_vulnerabilities(gen)
            if gen_vulns > src_vulns:
                count += 1
        return (count / len(source_codes)) * 100 if source_codes else 0

    def security_compliance_rate(self, gen_codes: List[str]) -> float:
        """
        Compute SCR (Equation 5). A command is compliant if no high/critical vulnerabilities.
        """
        compliant = 0
        for code in gen_codes:
            if not self.patterns.contains_critical(code) and not self.patterns.contains_high(code):
                compliant += 1
        return (compliant / len(gen_codes)) * 100 if gen_codes else 0

    def functional_correctness_rate(self, gen_codes: List[str], test_results: List[bool]) -> float:
        """Percentage passing functional tests."""
        return (sum(test_results) / len(gen_codes)) * 100 if gen_codes else 0

    def semantic_similarity(self, reference: str, candidate: str) -> float:
        """Return CodeBLEU score between reference and candidate."""
        return self.codebleu.compute(reference, candidate)

    def _count_vulnerabilities(self, code: str) -> int:
        count = 0
        for pat in self.patterns.critical_patterns:
            if re.search(pat, code, re.IGNORECASE):
                count += 1
        for pat in self.patterns.high_patterns:
            if re.search(pat, code, re.IGNORECASE):
                count += 1
        return count
