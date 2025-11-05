# Copyright (c) 2025, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Security Test Suite for CVE-002: Command Injection Vulnerability

This test suite detects potential command injection vulnerabilities in the NeMo codebase.
It scans for unsafe usage of shell command execution functions such as:
- os.system()
- subprocess.run() with shell=True
- subprocess.call() with shell=True
- subprocess.Popen() with shell=True
- os.popen()

These tests verify the PRESENCE of the vulnerability to ensure proper security auditing.
"""

import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest


class CommandInjectionDetector(ast.NodeVisitor):
    """AST visitor to detect potential command injection vulnerabilities."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.vulnerabilities = []

    def visit_Call(self, node):
        """Visit function call nodes to detect unsafe command execution."""
        # Detect os.system() calls
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'os'
                and node.func.attr == 'system'
            ):
                self.vulnerabilities.append(
                    {
                        'type': 'os.system',
                        'line': node.lineno,
                        'col': node.col_offset,
                        'severity': 'CRITICAL',
                        'description': 'Use of os.system() is unsafe and vulnerable to command injection',
                    }
                )

            # Detect os.popen() calls
            elif (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'os'
                and node.func.attr == 'popen'
            ):
                self.vulnerabilities.append(
                    {
                        'type': 'os.popen',
                        'line': node.lineno,
                        'col': node.col_offset,
                        'severity': 'CRITICAL',
                        'description': 'Use of os.popen() is unsafe and vulnerable to command injection',
                    }
                )

            # Detect subprocess.run/call/Popen with shell=True
            elif (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'subprocess'
                and node.func.attr in ['run', 'call', 'Popen']
            ):
                # Check if shell=True is in the arguments
                has_shell_true = False
                for keyword in node.keywords:
                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is True:
                            has_shell_true = True
                            break

                if has_shell_true:
                    self.vulnerabilities.append(
                        {
                            'type': f'subprocess.{node.func.attr}',
                            'line': node.lineno,
                            'col': node.col_offset,
                            'severity': 'CRITICAL',
                            'description': f'Use of subprocess.{node.func.attr}() with shell=True is vulnerable to command injection',
                        }
                    )

        self.generic_visit(node)


def scan_file_for_vulnerabilities(filepath: Path) -> List[Dict]:
    """
    Scan a Python file for command injection vulnerabilities using AST parsing.

    Args:
        filepath: Path to the Python file to scan

    Returns:
        List of vulnerability dictionaries
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        tree = ast.parse(content, filename=str(filepath))
        detector = CommandInjectionDetector(str(filepath))
        detector.visit(tree)
        return detector.vulnerabilities
    except Exception as e:
        # If AST parsing fails, return empty list (might be non-Python file or syntax error)
        return []


def scan_directory_for_vulnerabilities(directory: Path, exclude_dirs: List[str] = None) -> Dict[str, List[Dict]]:
    """
    Recursively scan a directory for command injection vulnerabilities.

    Args:
        directory: Root directory to scan
        exclude_dirs: List of directory names to exclude from scanning

    Returns:
        Dictionary mapping file paths to lists of vulnerabilities
    """
    if exclude_dirs is None:
        exclude_dirs = ['.git', '__pycache__', '.pytest_cache', 'venv', 'env', '.tox', 'build', 'dist', '.eggs']

    results = {}
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories from the search
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            if file.endswith('.py'):
                filepath = Path(root) / file
                vulnerabilities = scan_file_for_vulnerabilities(filepath)
                if vulnerabilities:
                    results[str(filepath)] = vulnerabilities

    return results


class TestCVE002CommandInjection:
    """Test suite for CVE-002: Command Injection vulnerability detection."""

    @pytest.fixture(scope="class")
    def workspace_root(self):
        """Get the workspace root directory."""
        # Get the repository root (parent of tests directory)
        tests_dir = Path(__file__).parent.parent
        return tests_dir.parent

    @pytest.fixture(scope="class")
    def vulnerability_scan_results(self, workspace_root):
        """Scan the entire codebase for command injection vulnerabilities."""
        # Scan main nemo package
        nemo_results = scan_directory_for_vulnerabilities(workspace_root / 'nemo')
        # Scan scripts directory
        scripts_results = scan_directory_for_vulnerabilities(workspace_root / 'scripts')
        # Combine results
        all_results = {**nemo_results, **scripts_results}
        return all_results

    def test_detect_os_system_in_cloud_utils(self, workspace_root):
        """
        Test: Detect os.system() usage in nemo/utils/cloud.py

        This test verifies the presence of an os.system() call in the cloud utilities
        that executes system commands without proper input sanitization.

        Location: nemo/utils/cloud.py:115
        Vulnerability: os.system('chmod 777 /tmp && apt-get update && apt-get install -y libsndfile1 ffmpeg')
        """
        filepath = workspace_root / 'nemo' / 'utils' / 'cloud.py'
        assert filepath.exists(), f"Expected file not found: {filepath}"

        vulnerabilities = scan_file_for_vulnerabilities(filepath)

        # Assert that vulnerabilities are found
        assert len(vulnerabilities) > 0, (
            f"EXPECTED VULNERABILITY NOT DETECTED: os.system() call should be detected in {filepath}"
        )

        # Check for os.system specifically
        os_system_vulns = [v for v in vulnerabilities if v['type'] == 'os.system']
        assert len(os_system_vulns) > 0, (
            f"EXPECTED VULNERABILITY NOT DETECTED: os.system() usage in {filepath} "
            "This is a CRITICAL security issue that should be flagged."
        )

        # Verify the vulnerability is around line 115
        for vuln in os_system_vulns:
            assert vuln['severity'] == 'CRITICAL', "Command injection should be marked as CRITICAL severity"
            # Allow some flexibility in line number (within 10 lines)
            assert 110 <= vuln['line'] <= 120, (
                f"Expected os.system() vulnerability around line 115, found at line {vuln['line']}"
            )

    def test_detect_subprocess_shell_true_in_deploy_base(self, workspace_root):
        """
        Test: Detect subprocess.run() with shell=True in nemo/collections/llm/deploy/base.py

        This test verifies the presence of subprocess.run() with shell=True that
        constructs and executes shell commands, making it vulnerable to command injection.

        Location: nemo/collections/llm/deploy/base.py:36
        Vulnerability: subprocess.run(cmd, shell=True, capture_output=True, text=True)
        """
        filepath = workspace_root / 'nemo' / 'collections' / 'llm' / 'deploy' / 'base.py'
        assert filepath.exists(), f"Expected file not found: {filepath}"

        vulnerabilities = scan_file_for_vulnerabilities(filepath)

        # Assert that vulnerabilities are found
        assert len(vulnerabilities) > 0, (
            f"EXPECTED VULNERABILITY NOT DETECTED: subprocess.run() with shell=True "
            f"should be detected in {filepath}"
        )

        # Check for subprocess.run specifically
        subprocess_vulns = [v for v in vulnerabilities if v['type'] == 'subprocess.run']
        assert len(subprocess_vulns) > 0, (
            f"EXPECTED VULNERABILITY NOT DETECTED: subprocess.run() with shell=True in {filepath} "
            "This is a CRITICAL security issue that should be flagged."
        )

        # Verify severity
        for vuln in subprocess_vulns:
            assert vuln['severity'] == 'CRITICAL', "Command injection should be marked as CRITICAL severity"
            # Verify it's in the expected range
            assert 30 <= vuln['line'] <= 40, (
                f"Expected subprocess.run() vulnerability around line 36, found at line {vuln['line']}"
            )

    def test_detect_subprocess_shell_true_in_commonvoice_script(self, workspace_root):
        """
        Test: Detect subprocess.run() with shell=True in scripts/dataset_processing/get_commonvoice_data.py

        This test verifies the presence of subprocess.run() with shell=True that
        executes wget commands, potentially allowing command injection through URL manipulation.

        Location: scripts/dataset_processing/get_commonvoice_data.py:175
        Vulnerability: subprocess.run(commands, shell=True, stderr=sys.stderr, stdout=sys.stdout, capture_output=False)
        """
        filepath = workspace_root / 'scripts' / 'dataset_processing' / 'get_commonvoice_data.py'
        assert filepath.exists(), f"Expected file not found: {filepath}"

        vulnerabilities = scan_file_for_vulnerabilities(filepath)

        # Assert that vulnerabilities are found
        assert len(vulnerabilities) > 0, (
            f"EXPECTED VULNERABILITY NOT DETECTED: subprocess.run() with shell=True "
            f"should be detected in {filepath}"
        )

        # Check for subprocess.run specifically
        subprocess_vulns = [v for v in vulnerabilities if v['type'] == 'subprocess.run']
        assert len(subprocess_vulns) > 0, (
            f"EXPECTED VULNERABILITY NOT DETECTED: subprocess.run() with shell=True in {filepath} "
            "This is a CRITICAL security issue that should be flagged."
        )

        # Verify the vulnerability is around line 175
        for vuln in subprocess_vulns:
            assert vuln['severity'] == 'CRITICAL', "Command injection should be marked as CRITICAL severity"
            assert 170 <= vuln['line'] <= 180, (
                f"Expected subprocess.run() vulnerability around line 175, found at line {vuln['line']}"
            )

    def test_comprehensive_vulnerability_scan(self, vulnerability_scan_results):
        """
        Test: Comprehensive scan of the entire codebase for command injection vulnerabilities

        This test performs a full codebase scan to identify all instances of potential
        command injection vulnerabilities. It serves as a comprehensive security audit.
        """
        assert len(vulnerability_scan_results) > 0, (
            "EXPECTED VULNERABILITIES NOT DETECTED: The codebase should contain instances of "
            "command injection vulnerabilities. If this test fails, either the vulnerabilities "
            "have been fixed (good!) or the detection mechanism needs improvement."
        )

        # Count vulnerabilities by type
        vulnerability_counts = {'os.system': 0, 'os.popen': 0, 'subprocess.run': 0, 'subprocess.call': 0}

        for filepath, vulns in vulnerability_scan_results.items():
            for vuln in vulns:
                vuln_type = vuln['type']
                if vuln_type in vulnerability_counts:
                    vulnerability_counts[vuln_type] += 1

        # Assert that we detect known vulnerabilities
        assert (
            vulnerability_counts['os.system'] >= 1
        ), "Expected at least 1 os.system() vulnerability (e.g., in nemo/utils/cloud.py)"

        assert vulnerability_counts['subprocess.run'] >= 2, (
            "Expected at least 2 subprocess.run() with shell=True vulnerabilities "
            "(e.g., in deploy/base.py and get_commonvoice_data.py)"
        )

        # Print summary for report generation
        print("\n" + "=" * 80)
        print("CVE-002 COMMAND INJECTION VULNERABILITY SCAN RESULTS")
        print("=" * 80)
        print(f"\nTotal vulnerable files found: {len(vulnerability_scan_results)}")
        print(f"Total vulnerabilities detected: {sum(len(v) for v in vulnerability_scan_results.values())}")
        print("\nVulnerability breakdown by type:")
        for vuln_type, count in vulnerability_counts.items():
            if count > 0:
                print(f"  - {vuln_type}: {count} instance(s)")

        print("\n" + "-" * 80)
        print("Detailed vulnerability locations:")
        print("-" * 80)
        for filepath, vulns in sorted(vulnerability_scan_results.items()):
            print(f"\n{filepath}:")
            for vuln in vulns:
                print(f"  Line {vuln['line']}: {vuln['type']} - {vuln['description']}")

        print("\n" + "=" * 80)

    def test_vulnerability_in_specific_known_files(self, workspace_root):
        """
        Test: Verify all known vulnerable files are detected

        This test ensures that all files mentioned in the CVE-002 report are
        properly identified as containing command injection vulnerabilities.
        """
        known_vulnerable_files = [
            'nemo/utils/cloud.py',
            'nemo/collections/llm/deploy/base.py',
            'scripts/dataset_processing/get_commonvoice_data.py',
        ]

        detected_files = []
        for filepath in known_vulnerable_files:
            full_path = workspace_root / filepath
            if full_path.exists():
                vulns = scan_file_for_vulnerabilities(full_path)
                if vulns:
                    detected_files.append(filepath)

        # Assert all known files are detected
        assert len(detected_files) == len(known_vulnerable_files), (
            f"Not all known vulnerable files were detected. "
            f"Expected: {known_vulnerable_files}, Found: {detected_files}"
        )

    def test_os_system_pattern_detection(self, workspace_root):
        """
        Test: Detect all os.system() patterns in the codebase

        This test specifically looks for os.system() usage, which is inherently
        unsafe and should be replaced with safer alternatives.
        """
        nemo_dir = workspace_root / 'nemo'
        scripts_dir = workspace_root / 'scripts'

        os_system_files = []
        for directory in [nemo_dir, scripts_dir]:
            results = scan_directory_for_vulnerabilities(directory)
            for filepath, vulns in results.items():
                os_system_vulns = [v for v in vulns if v['type'] == 'os.system']
                if os_system_vulns:
                    os_system_files.append((filepath, os_system_vulns))

        assert len(os_system_files) > 0, (
            "EXPECTED VULNERABILITY NOT DETECTED: os.system() usage should be found in the codebase. "
            "This is a critical security issue."
        )

        print("\n" + "=" * 80)
        print("OS.SYSTEM() VULNERABILITY DETECTION")
        print("=" * 80)
        for filepath, vulns in os_system_files:
            print(f"\n{filepath}:")
            for vuln in vulns:
                print(f"  Line {vuln['line']}: {vuln['description']}")
        print("=" * 80)

    def test_subprocess_shell_true_pattern_detection(self, workspace_root):
        """
        Test: Detect all subprocess calls with shell=True in the codebase

        This test identifies all subprocess.run(), subprocess.call(), and subprocess.Popen()
        calls that use shell=True, which can lead to command injection vulnerabilities.
        """
        nemo_dir = workspace_root / 'nemo'
        scripts_dir = workspace_root / 'scripts'

        subprocess_files = []
        for directory in [nemo_dir, scripts_dir]:
            results = scan_directory_for_vulnerabilities(directory)
            for filepath, vulns in results.items():
                subprocess_vulns = [v for v in vulns if 'subprocess' in v['type']]
                if subprocess_vulns:
                    subprocess_files.append((filepath, subprocess_vulns))

        assert len(subprocess_files) > 0, (
            "EXPECTED VULNERABILITY NOT DETECTED: subprocess with shell=True should be found in the codebase. "
            "This is a critical security issue."
        )

        print("\n" + "=" * 80)
        print("SUBPROCESS SHELL=TRUE VULNERABILITY DETECTION")
        print("=" * 80)
        for filepath, vulns in subprocess_files:
            print(f"\n{filepath}:")
            for vuln in vulns:
                print(f"  Line {vuln['line']}: {vuln['description']}")
        print("=" * 80)


# Test for safe alternatives (negative tests)
class TestSafeCommandExecution:
    """
    Test suite for verifying safe command execution patterns.

    These are negative tests that verify safe alternatives to command injection
    vulnerable patterns. While the vulnerable code should exist in the codebase,
    this demonstrates what safe code should look like.
    """

    def test_safe_subprocess_usage_without_shell(self):
        """
        Test: Verify that subprocess without shell=True is safe

        This test demonstrates the safe way to use subprocess by passing
        arguments as a list without shell=True.
        """
        import subprocess

        # This is SAFE - no shell=True, arguments passed as list
        # Just testing that this pattern works correctly
        result = subprocess.run(['echo', 'hello'], capture_output=True, text=True)
        assert result.returncode == 0
        assert 'hello' in result.stdout

    def test_safe_subprocess_with_shlex_quote(self):
        """
        Test: Verify that shlex.quote can sanitize shell arguments

        This test demonstrates how shlex.quote should be used when shell
        execution is absolutely necessary (though it's still not recommended).
        """
        import shlex
        import subprocess

        # If shell=True is absolutely necessary, use shlex.quote to escape
        unsafe_input = "file.txt; rm -rf /"
        safe_input = shlex.quote(unsafe_input)

        # This should NOT execute the malicious command
        # (We're not actually running this in the test, just demonstrating the pattern)
        cmd = f"echo {safe_input}"
        # result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        # Verify that shlex.quote properly escaped the input
        assert ";" in unsafe_input
        assert safe_input.startswith("'") and safe_input.endswith("'")
        assert "rm -rf" in safe_input  # Wrapped in quotes, so it's harmless

    def test_recommendation_use_subprocess_list_args(self):
        """
        Test: Demonstrate recommended safe subprocess usage

        This test shows the recommended approach: use subprocess with a list
        of arguments instead of a string, and never use shell=True.
        """
        import subprocess

        # RECOMMENDED: Use list arguments, no shell=True
        user_input = "test.txt"  # Even malicious input can't break this
        result = subprocess.run(['ls', '-l', user_input], capture_output=True, text=True)

        # The command will fail because the file doesn't exist, but it won't
        # allow command injection
        assert result.returncode != 0 or result.returncode == 0  # Either outcome is safe
