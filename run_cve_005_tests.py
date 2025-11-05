#!/usr/bin/env python3
"""
Standalone test runner for CVE-005 security tests.
This script runs the tests without loading pytest conftest files.
"""

import sys
import os
import re
import ast
import tempfile
from pathlib import Path
from typing import List, Dict

# Add the workspace to the path
sys.path.insert(0, '/workspace')

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def add_pass(self, test_name: str):
        self.passed += 1
        print(f"✓ PASSED: {test_name}")
    
    def add_fail(self, test_name: str, error: str):
        self.failed += 1
        self.errors.append({'test': test_name, 'error': error})
        print(f"✗ FAILED: {test_name}")
        print(f"  Error: {error[:200]}...")
    
    def total(self):
        return self.passed + self.failed
    
    def success_rate(self):
        if self.total() == 0:
            return 0
        return (self.passed / self.total()) * 100


def get_python_files(repo_root: Path) -> List[Path]:
    """Get all Python files in the repository"""
    python_files = []
    exclude_patterns = ['venv', '.venv', '__pycache__', '.git', '.pytest_cache', 'build', 'dist']
    
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)
    
    return python_files


def test_no_unsafe_yaml_load_standard_library(result: TestResult, repo_root: Path):
    """Test that no files use yaml.load() without SafeLoader from standard yaml library."""
    test_name = "test_no_unsafe_yaml_load_standard_library"
    
    try:
        python_files = get_python_files(repo_root)
        vulnerable_files = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check if file imports standard yaml library
                has_yaml_import = (
                    re.search(r'^import yaml\s*$', content, re.MULTILINE) or
                    re.search(r'^from yaml import', content, re.MULTILINE)
                )
                
                if not has_yaml_import:
                    continue
                
                # Check for unsafe yaml.load() patterns
                unsafe_pattern = r'yaml\.load\s*\([^)]+\)'
                matches = list(re.finditer(unsafe_pattern, content))
                
                for match in matches:
                    matched_text = match.group()
                    
                    # Skip safe patterns
                    if 'safe_load' in matched_text:
                        continue
                    if 'SafeLoader' in matched_text:
                        continue
                    
                    # Check context for ruamel.yaml with typ='safe'
                    context_start = max(0, match.start() - 300)
                    context = content[context_start:match.end()]
                    
                    if "YAML(typ='safe')" in context or 'YAML(typ="safe")' in context:
                        continue
                    
                    # Get line number and content
                    line_num = content[:match.start()].count('\n') + 1
                    lines = content.split('\n')
                    line_content = lines[line_num - 1].strip()
                    
                    # Skip comments and docstrings
                    if line_content.startswith('#'):
                        continue
                    
                    # Check if in docstring
                    in_docstring = False
                    docstring_count = 0
                    for i in range(line_num):
                        if '"""' in lines[i] or "'''" in lines[i]:
                            docstring_count += 1
                    if docstring_count % 2 == 1:  # Odd number means we're inside a docstring
                        continue
                    
                    vulnerable_files.append({
                        'file': str(py_file.relative_to(repo_root)),
                        'line': line_num,
                        'content': line_content
                    })
            
            except (UnicodeDecodeError, PermissionError):
                continue
        
        if vulnerable_files:
            error_msg = f"Found {len(vulnerable_files)} unsafe yaml.load() usage(s):\n"
            for vuln in vulnerable_files[:5]:  # Show first 5
                error_msg += f"  {vuln['file']}:{vuln['line']} - {vuln['content']}\n"
            result.add_fail(test_name, error_msg)
        else:
            result.add_pass(test_name)
    
    except Exception as e:
        result.add_fail(test_name, str(e))


def test_yaml_load_ast_analysis(result: TestResult, repo_root: Path):
    """Use AST analysis to detect unsafe yaml.load() calls."""
    test_name = "test_yaml_load_ast_analysis"
    
    try:
        python_files = get_python_files(repo_root)
        vulnerable_files = []
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                try:
                    tree = ast.parse(content, filename=str(py_file))
                except SyntaxError:
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
                        is_yaml_load = False
                        
                        if isinstance(node.func, ast.Attribute):
                            if (isinstance(node.func.value, ast.Name) and 
                                node.func.value.id == 'yaml' and 
                                node.func.attr == 'load'):
                                is_yaml_load = True
                        
                        if is_yaml_load:
                            has_safe_loader = False
                            
                            for keyword in node.keywords:
                                if keyword.arg == 'Loader':
                                    if isinstance(keyword.value, ast.Attribute):
                                        if (isinstance(keyword.value.value, ast.Name) and
                                            keyword.value.value.id == 'yaml' and
                                            keyword.value.attr == 'SafeLoader'):
                                            has_safe_loader = True
                            
                            if not has_safe_loader:
                                vulnerable_files.append({
                                    'file': str(py_file.relative_to(repo_root)),
                                    'line': node.lineno
                                })
            
            except (UnicodeDecodeError, PermissionError):
                continue
        
        if vulnerable_files:
            error_msg = f"AST analysis found {len(vulnerable_files)} unsafe yaml.load() call(s):\n"
            for vuln in vulnerable_files[:5]:
                error_msg += f"  {vuln['file']}:{vuln['line']}\n"
            result.add_fail(test_name, error_msg)
        else:
            result.add_pass(test_name)
    
    except Exception as e:
        result.add_fail(test_name, str(e))


def test_no_yaml_unsafe_load(result: TestResult, repo_root: Path):
    """Test that yaml.unsafe_load() is never used."""
    test_name = "test_no_yaml_unsafe_load"
    
    try:
        python_files = get_python_files(repo_root)
        files_with_unsafe_load = []
        
        for py_file in python_files:
            # Skip our own test files
            if 'test_cve_005' in str(py_file) or 'run_cve_005' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                matches = re.finditer(r'yaml\.unsafe_load\s*\(', content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    files_with_unsafe_load.append(f"{str(py_file.relative_to(repo_root))}:{line_num}")
            
            except (UnicodeDecodeError, PermissionError):
                continue
        
        if files_with_unsafe_load:
            file_list = '\n  '.join(files_with_unsafe_load[:10])
            result.add_fail(test_name, f"Found yaml.unsafe_load() in {len(files_with_unsafe_load)} file(s):\n  {file_list}")
        else:
            result.add_pass(test_name)
    
    except Exception as e:
        result.add_fail(test_name, str(e))


def test_malicious_yaml_payload_detection(result: TestResult):
    """Test that malicious YAML payloads are properly rejected by safe loaders."""
    test_name = "test_malicious_yaml_payload_detection"
    
    try:
        import yaml
        
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "VULNERABILITY_EXPLOITED"']
"""
        
        # Test that safe_load rejects malicious YAML
        try:
            yaml.safe_load(malicious_yaml)
            result.add_fail(test_name, "yaml.safe_load() did not reject malicious YAML")
            return
        except yaml.constructor.ConstructorError:
            pass  # Expected
        
        # Test that SafeLoader rejects malicious YAML
        try:
            yaml.load(malicious_yaml, Loader=yaml.SafeLoader)
            result.add_fail(test_name, "yaml.load() with SafeLoader did not reject malicious YAML")
            return
        except yaml.constructor.ConstructorError:
            pass  # Expected
        
        result.add_pass(test_name)
    
    except Exception as e:
        result.add_fail(test_name, str(e))


def test_yaml_load_with_safeloader_is_secure(result: TestResult):
    """Test that SafeLoader properly rejects various malicious payloads."""
    test_name = "test_yaml_load_with_safeloader_is_secure"
    
    try:
        import yaml
        
        malicious_payloads = [
            "!!python/object/apply:os.system ['echo pwned']",
            "!!python/object/new:os.system ['whoami']",
            "!!python/name:os.system",
        ]
        
        for payload in malicious_payloads:
            try:
                yaml.load(payload, Loader=yaml.SafeLoader)
                result.add_fail(test_name, f"SafeLoader did not reject payload: {payload[:50]}")
                return
            except yaml.constructor.ConstructorError:
                pass  # Expected
            
            try:
                yaml.safe_load(payload)
                result.add_fail(test_name, f"safe_load did not reject payload: {payload[:50]}")
                return
            except yaml.constructor.ConstructorError:
                pass  # Expected
        
        result.add_pass(test_name)
    
    except Exception as e:
        result.add_fail(test_name, str(e))


def test_yaml_safe_alternatives_work(result: TestResult):
    """Test that safe YAML loading alternatives work correctly."""
    test_name = "test_yaml_safe_alternatives_work"
    
    try:
        import yaml
        
        safe_yaml = """
name: test_config
version: 1.0
settings:
  batch_size: 32
  learning_rate: 0.001
"""
        
        config1 = yaml.safe_load(safe_yaml)
        config2 = yaml.load(safe_yaml, Loader=yaml.SafeLoader)
        
        if config1 != config2:
            result.add_fail(test_name, "safe_load and load with SafeLoader produce different results")
            return
        
        if config1['name'] != 'test_config':
            result.add_fail(test_name, "Failed to parse YAML correctly")
            return
        
        result.add_pass(test_name)
    
    except Exception as e:
        result.add_fail(test_name, str(e))


def main():
    print("=" * 70)
    print("CVE-005 Security Test Suite")
    print("Remote Code Execution via Unsafe YAML Loading")
    print("=" * 70)
    print()
    
    repo_root = Path('/workspace')
    result = TestResult()
    
    # Run all tests
    print("Running security tests...\n")
    
    test_no_unsafe_yaml_load_standard_library(result, repo_root)
    test_yaml_load_ast_analysis(result, repo_root)
    test_no_yaml_unsafe_load(result, repo_root)
    test_malicious_yaml_payload_detection(result)
    test_yaml_load_with_safeloader_is_secure(result)
    test_yaml_safe_alternatives_work(result)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests:   {result.total()}")
    print(f"Passed:        {result.passed}")
    print(f"Failed:        {result.failed}")
    print(f"Success Rate:  {result.success_rate():.1f}%")
    print("=" * 70)
    
    if result.failed > 0:
        print("\nFAILED TESTS:")
        for error in result.errors:
            print(f"\n{error['test']}:")
            print(f"  {error['error']}")
    
    return result


if __name__ == '__main__':
    result = main()
    sys.exit(0 if result.failed == 0 else 1)
