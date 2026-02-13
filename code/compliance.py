"""Algorithm 6: Multi-Layer Security Compliance Verification."""

from typing import Dict, List, Any, Tuple
from .ast_validator import ASTValidator
from .security_patterns import SecurityPatterns
from .secure_executor import SecureExecutor
from .metrics import CodeBLEU

class ComplianceVerifier:
    """Orchestrates multi-layer verification of generated code."""

    def __init__(self):
        self.ast_validator = ASTValidator()
        self.patterns = SecurityPatterns()
        self.executor = SecureExecutor()
        self.codebleu = CodeBLEU()

    def verify(self, generated: str, source: str, test_cases: List[Dict] = None) -> Tuple[bool, List[str]]:
        """
        Run all verification layers.

        Args:
            generated: The refactored PowerShell command.
            source: The original command (for semantic comparison).
            test_cases: Optional list of dicts with 'input' and 'expected_output'.

        Returns:
            (compliant, list_of_issues)
        """
        issues = []

        # Layer 1: Static Analysis
        ast_result = self.ast_validator.validate(generated)
        if not ast_result['pass']:
            issues.extend(ast_result['vulnerabilities'])

        # Layer 2: Pattern Matching
        source_vulns = self._count_vulnerabilities(source)
        gen_vulns = self._count_vulnerabilities(generated)
        if gen_vulns > source_vulns:
            issues.append("NEW_VULNERABILITY_INTRODUCED")

        # Layer 3: Sandboxed Execution (if test cases provided)
        if test_cases:
            for tc in test_cases:
                # Construct command with parameters
                exit_code, stdout, stderr = self.executor.execute_script(generated, context="sandbox")
                if exit_code != 0 or stdout.strip() != tc.get('expected', '').strip():
                    issues.append("FUNCTIONAL_INCORRECTNESS")
                    break

        # Layer 4: Semantic Preservation
        sim = self.codebleu.compute(source, generated)
        if sim < 0.5:  # threshold from paper
            issues.append("SEMANTIC_DRIFT")

        compliant = len(issues) == 0
        return compliant, issues

    def _count_vulnerabilities(self, code: str) -> int:
        """Count number of vulnerability patterns in code."""
        count = 0
        for pat in self.patterns.critical_patterns:
            if pat in code:
                count += 1
        for pat in self.patterns.high_patterns:
            if pat in code:
                count += 1
        return count
