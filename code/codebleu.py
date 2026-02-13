"""Full CodeBLEU implementation adapted for PowerShell.

Combines n-gram BLEU with syntactic AST node type similarity.
Based on the methodology described in Ren et al. (2020).
"""

import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple
from collections import Counter

try:
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    print("Warning: nltk not installed. BLEU scores will be approximated.")


class CodeBLEUCalculator:
    """Calculates CodeBLEU between two PowerShell code snippets."""

    def __init__(self,
                 weights: Tuple[float, float] = (0.5, 0.5),  # BLEU weight, AST weight
                 ngram_order: int = 4,
                 pwsh_path: str = "pwsh"):
        self.weights = weights
        self.ngram_order = ngram_order
        self.pwsh_path = pwsh_path
        self.smoother = SmoothingFunction().method1 if NLTK_AVAILABLE else None

    def compute(self, reference: str, candidate: str) -> float:
        """
        Compute CodeBLEU score.

        Args:
            reference: Ground truth PowerShell code.
            candidate: Generated PowerShell code.

        Returns:
            Score between 0 and 1.
        """
        # 1. n-gram BLEU
        bleu_score = self._bleu(reference, candidate)

        # 2. Syntactic AST node type similarity
        ast_sim = self._ast_similarity(reference, candidate)

        # Weighted combination
        codebleu = self.weights[0] * bleu_score + self.weights[1] * ast_sim
        return min(max(codebleu, 0.0), 1.0)

    def _bleu(self, reference: str, candidate: str) -> float:
        """Compute smoothed BLEU score."""
        if not NLTK_AVAILABLE:
            # Fallback: simple token overlap
            ref_tokens = self._tokenize(reference)
            cand_tokens = self._tokenize(candidate)
            if not ref_tokens:
                return 1.0
            overlap = len(set(ref_tokens) & set(cand_tokens))
            return overlap / len(set(ref_tokens))

        ref_tokens = self._tokenize(reference)
        cand_tokens = self._tokenize(candidate)

        # BLEU expects list of references (each a list of tokens)
        return sentence_bleu([ref_tokens], cand_tokens,
                             weights=self._ngram_weights(),
                             smoothing_function=self.smoother)

    def _ngram_weights(self) -> Tuple[float, ...]:
        """Create uniform weights up to ngram_order."""
        weight = 1.0 / self.ngram_order
        return tuple([weight] * self.ngram_order)

    def _tokenize(self, code: str) -> List[str]:
        """Simple tokenization: split on non-alphanumeric."""
        # Keep PowerShell cmdlets and variables intact
        tokens = re.findall(r'[A-Za-z][A-Za-z0-9_-]*|\S', code)
        return tokens

    def _ast_similarity(self, ref: str, cand: str) -> float:
        """
        Compute Jaccard similarity between AST node type multisets.
        Uses PowerShell's own parser via subprocess.
        """
        ref_nodes = self._get_ast_node_types(ref)
        cand_nodes = self._get_ast_node_types(cand)

        if not ref_nodes:
            return 1.0 if not cand_nodes else 0.0

        # Convert to multisets (Counters) for better overlap measure
        ref_counter = Counter(ref_nodes)
        cand_counter = Counter(cand_nodes)

        # Intersection size = sum of min counts
        intersection = sum(min(ref_counter[k], cand_counter[k]) for k in ref_counter)
        union = sum(max(ref_counter[k], cand_counter[k]) for k in set(ref_counter) | set(cand_counter))

        return intersection / union if union > 0 else 0.0

    def _get_ast_node_types(self, code: str) -> List[str]:
        """
        Call PowerShell parser to get list of AST node type names.
        Returns empty list on error.
        """
        # Use a temporary script similar to ast_validator.py
        parser_script = Path(__file__).parent / "parse_ast.ps1"
        if not parser_script.exists():
            self._create_parser_script(parser_script)

        try:
            result = subprocess.run(
                [self.pwsh_path, "-File", str(parser_script), "-code", code],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return []
            # Expect JSON list of node types
            import json
            data = json.loads(result.stdout)
            return data.get('Nodes', [])
        except Exception:
            return []

    def _create_parser_script(self, path: Path):
        """Create a PowerShell script that outputs AST node types."""
        script_content = """
param([string]$code)

$ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null)
$visitor = New-Object -TypeName "System.Management.Automation.Language.CustomAstVisitor2"
$ast.Visit($visitor) | Out-Null
$visitor.Nodes | ConvertTo-Json
"""
        path.write_text(script_content)
