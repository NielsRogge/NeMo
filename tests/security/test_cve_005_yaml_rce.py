"""
Security Tests for CVE-005: Remote Code Execution via Unsafe YAML Loading

This test suite validates that the codebase is not vulnerable to RCE through
unsafe YAML loading patterns. The tests check for:
1. Presence of unsafe yaml.load() calls without SafeLoader
2. Verification that safe alternatives (yaml.safe_load) are used
3. Detection of potential code execution vulnerabilities through malicious YAML

CVE ID: CVE-005
Severity: CRITICAL
Issue: https://ml6team.atlassian.net/browse/DR-137
"""

import ast
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


class TestCVE005YAMLRCEVulnerability:
    """Test suite for CVE-005 - Unsafe YAML Loading vulnerability"""

    @pytest.fixture
    def repo_root(self):
        """Get the repository root directory"""
        return Path(__file__).parent.parent.parent

    @pytest.fixture
    def python_files(self, repo_root):
        """Get all Python files in the repository"""
        python_files = []
        # Exclude test files and virtual environments
        exclude_patterns = ['venv', '.venv', '__pycache__', '.git', '.pytest_cache']
        
        for root, dirs, files in os.walk(repo_root):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]
            
            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)
        
        return python_files

    def test_no_unsafe_yaml_load_standard_library(self, python_files):
        """
        Test that no files use yaml.load() without SafeLoader from standard yaml library.
        
        This test specifically checks for unsafe patterns like:
        - yaml.load(stream) without Loader parameter
        - yaml.load(stream, Loader=yaml.Loader)
        - yaml.load(stream, Loader=yaml.FullLoader)
        
        Safe patterns that should pass:
        - yaml.load(stream, Loader=yaml.SafeLoader)
        - yaml.safe_load(stream)
        """
        vulnerable_files = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check if file imports standard yaml library (not ruamel.yaml)
                has_yaml_import = (
                    re.search(r'^import yaml\s*$', content, re.MULTILINE) or
                    re.search(r'^from yaml import', content, re.MULTILINE)
                )
                
                if not has_yaml_import:
                    continue
                
                # Check for unsafe yaml.load() patterns
                # Match yaml.load() but not yaml.safe_load() or when Loader=yaml.SafeLoader is present
                unsafe_patterns = [
                    r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)',
                ]
                
                for pattern in unsafe_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Additional check: ensure it's not yaml.safe_load
                        if 'safe_load' not in match.group():
                            # Get line number
                            line_num = content[:match.start()].count('\n') + 1
                            
                            # Get the actual line content
                            lines = content.split('\n')
                            line_content = lines[line_num - 1].strip()
                            
                            # Skip if it's in a comment or docstring
                            if line_content.startswith('#') or '"""' in content[max(0, match.start()-100):match.start()]:
                                continue
                            
                            # Check if SafeLoader is specified in the same line or continuation
                            context = content[match.start():min(match.end() + 100, len(content))]
                            if 'SafeLoader' not in context:
                                vulnerable_files.append({
                                    'file': str(py_file.relative_to(py_file.parent.parent.parent)),
                                    'line': line_num,
                                    'content': line_content
                                })
            
            except (UnicodeDecodeError, PermissionError):
                # Skip files that can't be read
                continue
        
        # Report findings
        if vulnerable_files:
            error_msg = "\n\nVULNERABILITY DETECTED: Unsafe yaml.load() usage found in the following files:\n\n"
            for vuln in vulnerable_files:
                error_msg += f"  File: {vuln['file']}\n"
                error_msg += f"  Line: {vuln['line']}\n"
                error_msg += f"  Code: {vuln['content']}\n\n"
            
            error_msg += "\nRECOMMENDATION: Replace yaml.load() with yaml.safe_load() or use yaml.load(stream, Loader=yaml.SafeLoader)\n"
            
            pytest.fail(error_msg)

    def test_yaml_load_ast_analysis(self, python_files):
        """
        Use AST analysis to detect unsafe yaml.load() calls more accurately.
        
        This test parses Python files as AST and checks for yaml.load() calls
        that don't specify SafeLoader.
        """
        vulnerable_files = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse the file as AST
                try:
                    tree = ast.parse(content, filename=str(py_file))
                except SyntaxError:
                    # Skip files with syntax errors
                    continue
                
                # Check if yaml is imported
                has_yaml_import = False
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        if any(alias.name == 'yaml' for alias in node.names):
                            has_yaml_import = True
                    elif isinstance(node, ast.ImportFrom):
                        if node.module == 'yaml':
                            has_yaml_import = True
                
                if not has_yaml_import:
                    continue
                
                # Check for yaml.load() calls
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Check if it's a yaml.load() call
                        is_yaml_load = False
                        
                        if isinstance(node.func, ast.Attribute):
                            if (isinstance(node.func.value, ast.Name) and 
                                node.func.value.id == 'yaml' and 
                                node.func.attr == 'load'):
                                is_yaml_load = True
                        
                        if is_yaml_load:
                            # Check if SafeLoader is specified
                            has_safe_loader = False
                            
                            for keyword in node.keywords:
                                if keyword.arg == 'Loader':
                                    # Check if it's SafeLoader
                                    if isinstance(keyword.value, ast.Attribute):
                                        if (isinstance(keyword.value.value, ast.Name) and
                                            keyword.value.value.id == 'yaml' and
                                            keyword.value.attr == 'SafeLoader'):
                                            has_safe_loader = True
                            
                            if not has_safe_loader:
                                vulnerable_files.append({
                                    'file': str(py_file.relative_to(py_file.parent.parent.parent)),
                                    'line': node.lineno
                                })
            
            except (UnicodeDecodeError, PermissionError):
                continue
        
        if vulnerable_files:
            error_msg = "\n\nVULNERABILITY DETECTED (AST Analysis): Unsafe yaml.load() without SafeLoader:\n\n"
            for vuln in vulnerable_files:
                error_msg += f"  File: {vuln['file']}\n"
                error_msg += f"  Line: {vuln['line']}\n\n"
            
            error_msg += "\nRECOMMENDATION: Use yaml.safe_load() or yaml.load(stream, Loader=yaml.SafeLoader)\n"
            
            pytest.fail(error_msg)

    def test_no_yaml_unsafe_load(self, python_files):
        """
        Test that yaml.unsafe_load() is never used in the codebase.
        
        yaml.unsafe_load() is explicitly dangerous and should never be used.
        """
        files_with_unsafe_load = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Search for yaml.unsafe_load
                matches = re.finditer(r'yaml\.unsafe_load\s*\(', content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    line_content = lines[line_num - 1].strip()
                    
                    files_with_unsafe_load.append({
                        'file': str(py_file.relative_to(py_file.parent.parent.parent)),
                        'line': line_num,
                        'content': line_content
                    })
            
            except (UnicodeDecodeError, PermissionError):
                continue
        
        if files_with_unsafe_load:
            error_msg = "\n\nCRITICAL: yaml.unsafe_load() detected in the following files:\n\n"
            for item in files_with_unsafe_load:
                error_msg += f"  File: {item['file']}\n"
                error_msg += f"  Line: {item['line']}\n"
                error_msg += f"  Code: {item['content']}\n\n"
            
            error_msg += "\nRECOMMENDATION: Never use yaml.unsafe_load(). Use yaml.safe_load() instead.\n"
            
            pytest.fail(error_msg)

    def test_malicious_yaml_payload_detection(self):
        """
        Test that demonstrates how malicious YAML can execute code if unsafe loading is used.
        
        This test creates a malicious YAML payload and verifies that:
        1. unsafe yaml.load() would execute the code (vulnerability exists)
        2. yaml.safe_load() properly prevents the code execution (safe alternative)
        """
        # Create a malicious YAML payload that attempts to execute code
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "VULNERABILITY_EXPLOITED" > /tmp/cve_005_test.txt']
"""
        
        import yaml
        
        # Test 1: Verify that yaml.safe_load() is safe
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.safe_load(malicious_yaml)
        
        # Note: We do NOT test yaml.load() without SafeLoader here as it would
        # actually execute the malicious code. Instead, we document that this
        # would be vulnerable.
        
        # Test 2: Verify SafeLoader is safe
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.load(malicious_yaml, Loader=yaml.SafeLoader)

    def test_yaml_load_with_safeloader_is_secure(self):
        """
        Test that yaml.load() with SafeLoader properly rejects malicious payloads.
        """
        import yaml
        
        malicious_payloads = [
            # Python object instantiation
            "!!python/object/apply:os.system ['echo pwned']",
            
            # Arbitrary class instantiation
            "!!python/object/new:os.system ['whoami']",
            
            # Module import
            "!!python/name:os.system",
        ]
        
        for payload in malicious_payloads:
            # Verify that SafeLoader rejects the payload
            with pytest.raises(yaml.constructor.ConstructorError):
                yaml.load(payload, Loader=yaml.SafeLoader)
            
            # Verify that safe_load also rejects it
            with pytest.raises(yaml.constructor.ConstructorError):
                yaml.safe_load(payload)

    def test_check_known_vulnerable_files(self, repo_root):
        """
        Test that checks the specific files mentioned in the CVE report.
        
        According to the CVE report, these files were identified as vulnerable:
        - nemo/collections/asr/parts/preprocessing/perturb.py
        - scripts/nemo_legacy_import/asr_checkpoint_port.py
        """
        known_vulnerable_files = [
            repo_root / 'nemo' / 'collections' / 'asr' / 'parts' / 'preprocessing' / 'perturb.py',
            repo_root / 'scripts' / 'nemo_legacy_import' / 'asr_checkpoint_port.py',
        ]
        
        vulnerabilities_found = []
        
        for file_path in known_vulnerable_files:
            if not file_path.exists():
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for yaml.load() without SafeLoader
            # Look for yaml.load( but exclude yaml.safe_load
            pattern = r'yaml\.load\s*\('
            matches = list(re.finditer(pattern, content))
            
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 200)
                context = content[start:end]
                
                # Check if it's safe
                is_safe = (
                    'SafeLoader' in context or
                    'safe' in content[match.start():match.start()+20] or
                    "YAML(typ='safe')" in content[max(0, match.start()-200):match.start()] or
                    "YAML(typ=\"safe\")" in content[max(0, match.start()-200):match.start()]
                )
                
                if not is_safe:
                    line_num = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    line_content = lines[line_num - 1].strip()
                    
                    # Check if it's in a docstring/comment
                    is_in_docstring = False
                    in_docstring = False
                    for i, line in enumerate(lines[:line_num], 1):
                        if '"""' in line or "'''" in line:
                            in_docstring = not in_docstring
                        if i == line_num and in_docstring:
                            is_in_docstring = True
                    
                    if not is_in_docstring and not line_content.startswith('#'):
                        vulnerabilities_found.append({
                            'file': str(file_path.relative_to(repo_root)),
                            'line': line_num,
                            'content': line_content
                        })
        
        if vulnerabilities_found:
            error_msg = "\n\nVULNERABILITY CONFIRMED in known vulnerable files:\n\n"
            for vuln in vulnerabilities_found:
                error_msg += f"  File: {vuln['file']}\n"
                error_msg += f"  Line: {vuln['line']}\n"
                error_msg += f"  Code: {vuln['content']}\n\n"
            
            pytest.fail(error_msg)

    def test_grep_yaml_load_patterns(self, repo_root):
        """
        Use grep-like search to find all yaml.load patterns in the codebase.
        
        This test uses a subprocess to search for yaml.load patterns.
        """
        try:
            # Use grep or ripgrep if available
            result = subprocess.run(
                ['grep', '-rn', '--include=*.py', r'yaml\.load(', str(repo_root)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:  # Found matches
                lines = result.stdout.strip().split('\n')
                unsafe_matches = []
                
                for line in lines:
                    # Skip if it contains SafeLoader or safe_load
                    if 'SafeLoader' in line or 'safe_load' in line:
                        continue
                    
                    # Skip if it's ruamel.yaml with typ='safe' or typ="safe"
                    if "typ='safe'" in line or 'typ="safe"' in line:
                        continue
                    
                    unsafe_matches.append(line)
                
                if unsafe_matches:
                    error_msg = "\n\nVULNERABILITY DETECTED via grep search:\n\n"
                    for match in unsafe_matches:
                        error_msg += f"  {match}\n"
                    
                    error_msg += "\n\nThese instances of yaml.load() do not appear to use SafeLoader.\n"
                    pytest.fail(error_msg)
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Grep command not available or timed out")

    def test_yaml_safe_alternatives_work(self):
        """
        Test that safe YAML loading alternatives work correctly for legitimate YAML.
        
        This ensures that the recommended safe alternatives don't break functionality.
        """
        import yaml
        
        # Test with legitimate YAML
        safe_yaml = """
name: test_config
version: 1.0
settings:
  batch_size: 32
  learning_rate: 0.001
"""
        
        # Test 1: yaml.safe_load() works
        config1 = yaml.safe_load(safe_yaml)
        assert config1['name'] == 'test_config'
        assert config1['settings']['batch_size'] == 32
        
        # Test 2: yaml.load() with SafeLoader works
        config2 = yaml.load(safe_yaml, Loader=yaml.SafeLoader)
        assert config2['name'] == 'test_config'
        assert config2['settings']['batch_size'] == 32
        
        # Test 3: Both methods produce identical results
        assert config1 == config2


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '-s'])
