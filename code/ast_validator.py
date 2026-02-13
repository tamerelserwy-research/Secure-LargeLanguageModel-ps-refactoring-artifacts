"""Algorithm 3: AST-Based Static Analysis Validation."""

import subprocess
import tempfile
import json
from pathlib import Path
from typing import List, Dict, Set

class ASTValidator:
    """
    Validates PowerShell code by parsing its abstract syntax tree.
    Uses PowerShell's own parser via subprocess.
    """

    def __init__(self, pwsh_path: str = "pwsh"):
        self.pwsh_path = pwsh_path
        # Script to parse AST and detect dangerous constructs
        self.parser_script = Path(__file__).parent / "parse_ast.ps1"
        # Create a temporary PowerShell script if not exists
        if not self.parser_script.exists():
            self._create_parser_script()

    def _create_parser_script(self):
        """Create a PowerShell script that outputs AST node types."""
        script_content = """
param([string]$code)

$ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null)
$visitor = New-Object -TypeName "System.Management.Automation.Language.CustomAstVisitor2"
$ast.Visit($visitor) | Out-Null
$visitor.Nodes | ConvertTo-Json
"""
        self.parser_script.write_text(script_content)

    def validate(self, code: str) -> Dict[str, any]:
        """
        Run AST analysis and return a dict with vulnerabilities.

        Returns:
            {
                'pass': bool,
                'vulnerabilities': List[str],
                'node_types': List[str]
            }
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write(code)
            script_path = f.name

        try:
            # Invoke PowerShell parser
            result = subprocess.run(
                [self.pwsh_path, "-File", str(self.parser_script), "-code", code],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return {'pass': False, 'vulnerabilities': ['Parser error'], 'node_types': []}

            data = json.loads(result.stdout)
            node_types = data.get('Nodes', [])
            vulns = self._detect_vulnerabilities(node_types, code)
            return {
                'pass': len(vulns) == 0,
                'vulnerabilities': vulns,
                'node_types': node_types
            }
        except Exception as e:
            return {'pass': False, 'vulnerabilities': [str(e)], 'node_types': []}
        finally:
            Path(script_path).unlink(missing_ok=True)

    def _detect_vulnerabilities(self, node_types: List[str], code: str) -> List[str]:
        """Map node types to CWE vulnerabilities."""
        vulns = []
        # InvokeExpressionAst
        if 'InvokeExpressionAst' in node_types:
            vulns.append('CWE-78: OS Command Injection (Invoke-Expression)')
        # DownloadString usage
        if 'MemberExpressionAst' in node_types and 'DownloadString' in code:
            vulns.append('CWE-494: Download of Code Without Integrity Check')
        # EncodedCommand
        if '-EncodedCommand' in code or 'EncodedCommand' in node_types:
            vulns.append('CWE-693: Protection Mechanism Failure (Encoded Command)')
        return vulns
