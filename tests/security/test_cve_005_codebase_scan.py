# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
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
Codebase scanning tests for CVE-005: Remote Code Execution via Unsafe YAML Loading

This module contains automated scanning tests to detect unsafe YAML loading
patterns across the entire NeMo codebase.

CVE-005 Affected Files (as documented):
- nemo/collections/asr/parts/preprocessing/perturb.py:1213
- scripts/nemo_legacy_import/asr_checkpoint_port.py:49
"""

import ast
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple

import pytest


class YAMLSecurityScanner:
    """
    Scanner class to detect unsafe YAML loading patterns in Python code.
    """

    def __init__(self, codebase_root: Path):
        self.codebase_root = codebase_root
        self.findings = []

    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a single Python file for unsafe YAML loading patterns.
        
        Returns:
            List of findings with file, line number, and issue description
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                # Skip comments and docstrings
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue
                
                # Pattern 1: yaml.load( without SafeLoader
                if re.search(r'yaml\.load\s*\([^)]*\)', line):
                    if 'SafeLoader' not in line and 'typ=' not in line:
                        findings.append({
                            'file': str(file_path.relative_to(self.codebase_root)),
                            'line': line_num,
                            'issue': 'yaml.load() without SafeLoader',
                            'content': stripped,
                            'severity': 'CRITICAL'
                        })
                
                # Pattern 2: yaml.unsafe_load(
                if 'yaml.unsafe_load' in line:
                    findings.append({
                        'file': str(file_path.relative_to(self.codebase_root)),
                        'line': line_num,
                        'issue': 'yaml.unsafe_load() explicitly unsafe',
                        'content': stripped,
                        'severity': 'CRITICAL'
                    })
                
                # Pattern 3: yaml.load with FullLoader (less secure than SafeLoader)
                if 'yaml.load' in line and 'FullLoader' in line:
                    findings.append({
                        'file': str(file_path.relative_to(self.codebase_root)),
                        'line': line_num,
                        'issue': 'yaml.load() with FullLoader (use SafeLoader)',
                        'content': stripped,
                        'severity': 'HIGH'
                    })
                
                # Pattern 4: YAML() without typ='safe'
                if re.search(r'YAML\s*\([^)]*\)', line):
                    if "typ='safe'" not in line and 'typ="safe"' not in line:
                        # Check if YAML is instantiated without typ parameter
                        if re.search(r'YAML\s*\(\s*\)', line) or (re.search(r'YAML\s*\(', line) and 'typ' not in line):
                            findings.append({
                                'file': str(file_path.relative_to(self.codebase_root)),
                                'line': line_num,
                                'issue': "YAML() without typ='safe'",
                                'content': stripped,
                                'severity': 'HIGH'
                            })
                        
        except Exception as e:
            # Skip files that can't be read
            pass
            
        return findings

    def scan_codebase(self, exclude_patterns: List[str] = None) -> List[Dict]:
        """
        Scan the entire codebase for unsafe YAML patterns.
        
        Args:
            exclude_patterns: List of patterns to exclude from scanning
            
        Returns:
            List of all findings
        """
        if exclude_patterns is None:
            exclude_patterns = ['test_', '__pycache__', '.git', 'build', 'dist', '.eggs']
        
        all_findings = []
        
        # Find all Python files
        for py_file in self.codebase_root.rglob('*.py'):
            # Skip excluded patterns
            if any(pattern in str(py_file) for pattern in exclude_patterns):
                continue
                
            findings = self.scan_file(py_file)
            all_findings.extend(findings)
        
        return all_findings


class TestCVE005CodebaseScan:
    """
    Automated codebase scanning tests for CVE-005.
    """

    @pytest.fixture
    def codebase_root(self):
        """Get the root directory of the NeMo codebase."""
        test_dir = Path(__file__).parent
        return test_dir.parent.parent

    @pytest.fixture
    def scanner(self, codebase_root):
        """Create a YAML security scanner instance."""
        return YAMLSecurityScanner(codebase_root)

    def test_scan_known_vulnerable_files(self, scanner, codebase_root):
        """
        Test the specific files mentioned in CVE-005 report.
        
        Files mentioned in CVE-005:
        - nemo/collections/asr/parts/preprocessing/perturb.py:1213
        - scripts/nemo_legacy_import/asr_checkpoint_port.py:49
        """
        vulnerable_files = [
            codebase_root / "nemo" / "collections" / "asr" / "parts" / "preprocessing" / "perturb.py",
            codebase_root / "scripts" / "nemo_legacy_import" / "asr_checkpoint_port.py",
        ]
        
        all_findings = []
        
        for file_path in vulnerable_files:
            if not file_path.exists():
                pytest.skip(f"File not found: {file_path}")
                continue
            
            findings = scanner.scan_file(file_path)
            all_findings.extend(findings)
        
        if all_findings:
            report = "\n" + "="*80 + "\n"
            report += "CVE-005 VULNERABILITY DETECTED IN KNOWN FILES\n"
            report += "="*80 + "\n\n"
            
            for finding in all_findings:
                report += f"[{finding['severity']}] {finding['file']}:{finding['line']}\n"
                report += f"  Issue: {finding['issue']}\n"
                report += f"  Code: {finding['content']}\n\n"
            
            report += "="*80 + "\n"
            report += "REMEDIATION:\n"
            report += "Replace yaml.load(stream) with:\n"
            report += "  - yaml.safe_load(stream), or\n"
            report += "  - yaml.load(stream, Loader=yaml.SafeLoader)\n"
            report += "="*80 + "\n"
            
            pytest.fail(report)

    def test_scan_export_module(self, scanner, codebase_root):
        """
        Scan the export module for unsafe YAML loading.
        
        The export module handles model configurations and is critical.
        """
        export_dir = codebase_root / "nemo" / "export"
        
        if not export_dir.exists():
            pytest.skip("Export directory not found")
        
        findings = []
        for py_file in export_dir.rglob('*.py'):
            findings.extend(scanner.scan_file(py_file))
        
        if findings:
            report = f"\nUnsafe YAML loading found in export module ({len(findings)} instances):\n"
            for f in findings[:10]:  # Show first 10
                report += f"  - {f['file']}:{f['line']} - {f['issue']}\n"
            pytest.fail(report)

    def test_scan_collections_module(self, scanner, codebase_root):
        """
        Scan the collections module for unsafe YAML loading.
        
        Collections contain various model implementations that may load configs.
        """
        collections_dir = codebase_root / "nemo" / "collections"
        
        if not collections_dir.exists():
            pytest.skip("Collections directory not found")
        
        findings = []
        for py_file in collections_dir.rglob('*.py'):
            # Focus on config loading files
            if 'config' in py_file.name.lower() or 'utils' in py_file.name.lower():
                findings.extend(scanner.scan_file(py_file))
        
        if findings:
            report = f"\nUnsafe YAML loading found in collections module ({len(findings)} instances):\n"
            for f in findings[:10]:
                report += f"  - {f['file']}:{f['line']} - {f['issue']}\n"
            pytest.fail(report)

    def test_full_codebase_scan(self, scanner):
        """
        Comprehensive scan of the entire codebase.
        
        This test scans all Python files (excluding tests) for unsafe YAML patterns.
        WARNING: This may take some time on large codebases.
        """
        # Exclude test files to focus on production code
        findings = scanner.scan_codebase(exclude_patterns=[
            'test_', 'tests/', '__pycache__', '.git', 'build', 'dist',
            '.eggs', 'tutorials/', 'examples/'
        ])
        
        if findings:
            # Group findings by severity
            critical = [f for f in findings if f['severity'] == 'CRITICAL']
            high = [f for f in findings if f['severity'] == 'HIGH']
            
            report = "\n" + "="*80 + "\n"
            report += "CVE-005 FULL CODEBASE SCAN RESULTS\n"
            report += "="*80 + "\n\n"
            report += f"Total Issues Found: {len(findings)}\n"
            report += f"  - CRITICAL: {len(critical)}\n"
            report += f"  - HIGH: {len(high)}\n\n"
            
            if critical:
                report += "CRITICAL ISSUES:\n"
                report += "-" * 80 + "\n"
                for f in critical[:20]:  # Show first 20 critical issues
                    report += f"{f['file']}:{f['line']} - {f['issue']}\n"
                    report += f"  Code: {f['content']}\n\n"
            
            if high:
                report += "\nHIGH SEVERITY ISSUES:\n"
                report += "-" * 80 + "\n"
                for f in high[:10]:  # Show first 10 high severity issues
                    report += f"{f['file']}:{f['line']} - {f['issue']}\n"
            
            report += "\n" + "="*80 + "\n"
            pytest.fail(report)

    def test_check_yaml_imports(self, codebase_root):
        """
        Check all files that import yaml to ensure safe usage.
        
        This test finds all files importing yaml and verifies they use safe patterns.
        """
        files_with_yaml_import = []
        
        for py_file in codebase_root.rglob('*.py'):
            # Skip test files and cache
            if 'test_' in py_file.name or '__pycache__' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                if 'import yaml' in content or 'from yaml import' in content:
                    files_with_yaml_import.append(py_file)
            except Exception:
                continue
        
        # Now check each file for safe usage
        unsafe_files = []
        for py_file in files_with_yaml_import:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Look for yaml.load without SafeLoader
                if re.search(r'yaml\.load\s*\([^)]*\)', content):
                    # Check if any usage doesn't have SafeLoader
                    loads = re.findall(r'yaml\.load\s*\([^)]*\)', content)
                    for load_call in loads:
                        if 'SafeLoader' not in load_call and 'safe_load' not in load_call:
                            unsafe_files.append(str(py_file.relative_to(codebase_root)))
                            break
            except Exception:
                continue
        
        if unsafe_files:
            report = f"\nFiles importing yaml with potentially unsafe usage ({len(unsafe_files)}):\n"
            for f in unsafe_files[:20]:
                report += f"  - {f}\n"
            report += "\nThese files should be reviewed to ensure yaml.safe_load() is used.\n"
            pytest.fail(report)


class TestCVE005SpecificLines:
    """
    Tests targeting the exact lines mentioned in the CVE-005 report.
    """

    @pytest.fixture
    def codebase_root(self):
        """Get the root directory of the NeMo codebase."""
        test_dir = Path(__file__).parent
        return test_dir.parent.parent

    def test_perturb_py_line_1213(self, codebase_root):
        """
        Test the specific line in perturb.py mentioned in CVE-005.
        
        CVE mentions: perturb.py:1213: params = yaml.load(f)
        """
        file_path = codebase_root / "nemo" / "collections" / "asr" / "parts" / "preprocessing" / "perturb.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Check around line 1213 (accounting for potential line number changes)
        check_range = range(max(1200, 1), min(1230, len(lines)))
        
        unsafe_loads = []
        for line_num in check_range:
            line = lines[line_num - 1]  # Convert to 0-indexed
            
            if 'yaml.load(' in line:
                # Check if it's the unsafe version
                if 'SafeLoader' not in line and 'typ=' not in line and not line.strip().startswith('#'):
                    unsafe_loads.append({
                        'line': line_num,
                        'content': line.strip()
                    })
        
        if unsafe_loads:
            report = f"\nUnsafe yaml.load() found in perturb.py:\n"
            for item in unsafe_loads:
                report += f"  Line {item['line']}: {item['content']}\n"
            pytest.fail(report)

    def test_asr_checkpoint_port_py_line_49(self, codebase_root):
        """
        Test the specific line in asr_checkpoint_port.py mentioned in CVE-005.
        
        CVE mentions: asr_checkpoint_port.py:49: params = yaml.load(f)
        """
        file_path = codebase_root / "scripts" / "nemo_legacy_import" / "asr_checkpoint_port.py"
        
        if not file_path.exists():
            pytest.skip(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Check around line 49
        check_range = range(max(40, 1), min(60, len(lines)))
        
        unsafe_loads = []
        for line_num in check_range:
            line = lines[line_num - 1]
            
            if 'yaml.load(' in line:
                if 'SafeLoader' not in line and 'typ=' not in line and not line.strip().startswith('#'):
                    unsafe_loads.append({
                        'line': line_num,
                        'content': line.strip()
                    })
        
        if unsafe_loads:
            report = f"\nUnsafe yaml.load() found in asr_checkpoint_port.py:\n"
            for item in unsafe_loads:
                report += f"  Line {item['line']}: {item['content']}\n"
            pytest.fail(report)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
