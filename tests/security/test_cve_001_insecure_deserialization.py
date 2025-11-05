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
Security tests for CVE-001: Insecure Deserialization

These tests verify the presence of insecure deserialization vulnerabilities in the codebase.
The vulnerability involves the use of torch.load, pickle.load, and pickle.loads without
proper security measures, which can lead to remote code execution if untrusted models are loaded.

IMPORTANT: These tests are designed to DETECT vulnerabilities, not fix them.
"""

import ast
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

import pytest


# Workspace root directory
WORKSPACE_ROOT = Path(__file__).parent.parent.parent

# Disable conftest to avoid dependency issues
pytest_plugins = []
collect_ignore = ['conftest.py']


class InsecureDeserializationDetector(ast.NodeVisitor):
    """AST visitor to detect insecure deserialization patterns."""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.vulnerabilities = []
        
    def visit_Call(self, node):
        """Visit function calls to detect insecure patterns."""
        # Check for torch.load with weights_only=False
        if self._is_torch_load_unsafe(node):
            line_num = node.lineno
            self.vulnerabilities.append({
                'type': 'torch.load',
                'line': line_num,
                'pattern': 'torch.load(..., weights_only=False)',
                'file': self.filename
            })
        
        # Check for pickle.load/pickle.loads
        if self._is_pickle_load(node):
            line_num = node.lineno
            func_name = self._get_function_name(node)
            self.vulnerabilities.append({
                'type': 'pickle',
                'line': line_num,
                'pattern': func_name,
                'file': self.filename
            })
        
        self.generic_visit(node)
    
    def _is_torch_load_unsafe(self, node):
        """Check if this is torch.load with weights_only=False or without weights_only parameter."""
        func_name = self._get_function_name(node)
        if func_name not in ['torch.load']:
            return False
        
        # Check if weights_only=False is explicitly set
        for keyword in node.keywords:
            if keyword.arg == 'weights_only':
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    return True
        
        return False
    
    def _is_pickle_load(self, node):
        """Check if this is pickle.load or pickle.loads."""
        func_name = self._get_function_name(node)
        return func_name in ['pickle.load', 'pickle.loads']
    
    def _get_function_name(self, node):
        """Extract the full function name from a Call node."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""


def scan_file_for_vulnerabilities(filepath: Path) -> List[dict]:
    """Scan a Python file for insecure deserialization patterns."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        
        tree = ast.parse(source, filename=str(filepath))
        detector = InsecureDeserializationDetector(str(filepath))
        detector.visit(tree)
        return detector.vulnerabilities
    except (SyntaxError, UnicodeDecodeError, Exception):
        # Skip files that can't be parsed
        return []


def find_python_files(root_dir: Path, exclude_dirs: set = None) -> List[Path]:
    """Find all Python files in the given directory, excluding specified directories."""
    if exclude_dirs is None:
        exclude_dirs = {'.git', '__pycache__', '.pytest_cache', 'build', 'dist', '.eggs'}
    
    python_files = []
    for root, dirs, files in os.walk(root_dir):
        # Remove excluded directories from dirs to prevent os.walk from traversing them
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)
    
    return python_files


class TestCVE001InsecureDeserialization:
    """Test suite for CVE-001: Insecure Deserialization vulnerability."""
    
    def test_detect_torch_load_with_weights_only_false(self):
        """
        Test: Detect torch.load calls with weights_only=False
        
        This test scans the codebase for torch.load() calls that explicitly set
        weights_only=False, which allows arbitrary code execution during deserialization.
        
        Expected: This test should PASS (find vulnerabilities), confirming the CVE exists.
        """
        vulnerabilities = []
        
        # Scan nemo directory
        nemo_dir = WORKSPACE_ROOT / 'nemo'
        if nemo_dir.exists():
            python_files = find_python_files(nemo_dir)
            
            for py_file in python_files:
                vulns = scan_file_for_vulnerabilities(py_file)
                torch_vulns = [v for v in vulns if v['type'] == 'torch.load']
                vulnerabilities.extend(torch_vulns)
        
        # Assert that vulnerabilities are found
        assert len(vulnerabilities) > 0, (
            "Expected to find torch.load with weights_only=False, but none were detected. "
            "This may indicate the vulnerability has been patched."
        )
        
        print(f"\n[CVE-001] Found {len(vulnerabilities)} instances of torch.load with weights_only=False:")
        for vuln in vulnerabilities[:10]:  # Show first 10
            print(f"  - {vuln['file']}:{vuln['line']}")
    
    def test_detect_pickle_load_in_codebase(self):
        """
        Test: Detect pickle.load usage in the codebase
        
        This test scans for pickle.load() calls, which can execute arbitrary code
        when deserializing untrusted data.
        
        Expected: This test should PASS (find vulnerabilities), confirming the CVE exists.
        """
        vulnerabilities = []
        
        # Scan nemo directory
        nemo_dir = WORKSPACE_ROOT / 'nemo'
        if nemo_dir.exists():
            python_files = find_python_files(nemo_dir)
            
            for py_file in python_files:
                vulns = scan_file_for_vulnerabilities(py_file)
                pickle_vulns = [v for v in vulns if v['type'] == 'pickle']
                vulnerabilities.extend(pickle_vulns)
        
        # Also scan tools directory
        tools_dir = WORKSPACE_ROOT / 'tools'
        if tools_dir.exists():
            python_files = find_python_files(tools_dir)
            
            for py_file in python_files:
                vulns = scan_file_for_vulnerabilities(py_file)
                pickle_vulns = [v for v in vulns if v['type'] == 'pickle']
                vulnerabilities.extend(pickle_vulns)
        
        # Assert that vulnerabilities are found
        assert len(vulnerabilities) > 0, (
            "Expected to find pickle.load/pickle.loads usage, but none were detected. "
            "This may indicate the vulnerability has been patched."
        )
        
        print(f"\n[CVE-001] Found {len(vulnerabilities)} instances of pickle.load/pickle.loads:")
        for vuln in vulnerabilities[:10]:  # Show first 10
            print(f"  - {vuln['file']}:{vuln['line']} - {vuln['pattern']}")
    
    def test_specific_vulnerable_file_save_restore_connector(self):
        """
        Test: Verify specific vulnerable file mentioned in CVE
        
        File: nemo/core/connectors/save_restore_connector.py
        Line: ~760
        Pattern: torch.load(model_weights, map_location='cpu', weights_only=False)
        
        Expected: This test should PASS, confirming the specific vulnerability exists.
        """
        target_file = WORKSPACE_ROOT / 'nemo' / 'core' / 'connectors' / 'save_restore_connector.py'
        
        assert target_file.exists(), f"Target file {target_file} does not exist"
        
        # Read the file and check for the vulnerable pattern
        with open(target_file, 'r') as f:
            content = f.read()
        
        # Check for torch.load with weights_only=False
        pattern = r'torch\.load\([^)]*weights_only=False[^)]*\)'
        matches = re.finditer(pattern, content)
        
        match_count = 0
        for match in matches:
            match_count += 1
            # Find line number
            line_num = content[:match.start()].count('\n') + 1
            print(f"\n[CVE-001] Found vulnerable pattern in {target_file.name}:{line_num}")
        
        assert match_count > 0, (
            f"Expected to find torch.load with weights_only=False in {target_file}, "
            "but the pattern was not detected. The vulnerability may have been patched."
        )
    
    def test_specific_vulnerable_file_data_explorer(self):
        """
        Test: Verify specific vulnerable file mentioned in CVE
        
        File: tools/speech_data_explorer/data_explorer.py
        Line: ~190
        Pattern: pickle.load(f)
        
        Expected: This test should PASS, confirming the specific vulnerability exists.
        """
        target_file = WORKSPACE_ROOT / 'tools' / 'speech_data_explorer' / 'data_explorer.py'
        
        assert target_file.exists(), f"Target file {target_file} does not exist"
        
        # Read the file and check for the vulnerable pattern
        with open(target_file, 'r') as f:
            content = f.read()
        
        # Check for pickle.load
        pattern = r'pickle\.load\s*\('
        matches = re.finditer(pattern, content)
        
        match_count = 0
        for match in matches:
            match_count += 1
            # Find line number
            line_num = content[:match.start()].count('\n') + 1
            print(f"\n[CVE-001] Found vulnerable pattern in {target_file.name}:{line_num}")
        
        assert match_count > 0, (
            f"Expected to find pickle.load in {target_file}, "
            "but the pattern was not detected. The vulnerability may have been patched."
        )
    
    def test_torch_load_without_weights_only_parameter(self):
        """
        Test: Detect torch.load calls without the weights_only parameter
        
        Using torch.load without explicitly setting weights_only=True is unsafe
        as the default behavior allows arbitrary code execution.
        
        Expected: This test should PASS (find instances), indicating potential vulnerabilities.
        """
        vulnerabilities = []
        
        # Scan nemo directory for torch.load usage
        nemo_dir = WORKSPACE_ROOT / 'nemo'
        if nemo_dir.exists():
            python_files = find_python_files(nemo_dir)
            
            for py_file in python_files:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Find torch.load calls
                # This regex looks for torch.load that doesn't have weights_only=True
                lines = content.split('\n')
                for i, line in enumerate(lines, 1):
                    if 'torch.load' in line:
                        # Check if this line has weights_only parameter
                        if 'weights_only' not in line:
                            vulnerabilities.append({
                                'file': str(py_file),
                                'line': i,
                                'content': line.strip()
                            })
        
        # We expect to find instances (even if not all are necessarily vulnerable)
        assert len(vulnerabilities) > 0, (
            "Expected to find torch.load calls without explicit weights_only parameter. "
            "If none found, the codebase may have been secured."
        )
        
        print(f"\n[CVE-001] Found {len(vulnerabilities)} instances of torch.load without explicit weights_only:")
        for vuln in vulnerabilities[:5]:  # Show first 5
            print(f"  - {vuln['file']}:{vuln['line']}")
    
    def test_comprehensive_vulnerability_summary(self):
        """
        Test: Generate a comprehensive summary of all insecure deserialization vulnerabilities
        
        This test provides an overall assessment of the CVE-001 vulnerability across the codebase.
        
        Expected: This test should PASS and report the total count of vulnerabilities found.
        """
        total_vulnerabilities = {
            'torch_load_unsafe': [],
            'pickle_load': [],
            'pickle_loads': []
        }
        
        # Scan nemo directory
        nemo_dir = WORKSPACE_ROOT / 'nemo'
        if nemo_dir.exists():
            python_files = find_python_files(nemo_dir)
            
            for py_file in python_files:
                # Check for torch.load with weights_only=False
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # torch.load with weights_only=False
                if re.search(r'torch\.load\([^)]*weights_only=False', content):
                    total_vulnerabilities['torch_load_unsafe'].append(str(py_file))
                
                # pickle.load
                if re.search(r'pickle\.load\s*\(', content):
                    total_vulnerabilities['pickle_load'].append(str(py_file))
                
                # pickle.loads
                if re.search(r'pickle\.loads\s*\(', content):
                    total_vulnerabilities['pickle_loads'].append(str(py_file))
        
        # Scan tools directory
        tools_dir = WORKSPACE_ROOT / 'tools'
        if tools_dir.exists():
            python_files = find_python_files(tools_dir)
            
            for py_file in python_files:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # pickle.load
                if re.search(r'pickle\.load\s*\(', content):
                    total_vulnerabilities['pickle_load'].append(str(py_file))
                
                # pickle.loads
                if re.search(r'pickle\.loads\s*\(', content):
                    total_vulnerabilities['pickle_loads'].append(str(py_file))
        
        total_count = (
            len(total_vulnerabilities['torch_load_unsafe']) +
            len(total_vulnerabilities['pickle_load']) +
            len(total_vulnerabilities['pickle_loads'])
        )
        
        print("\n" + "="*80)
        print("[CVE-001] INSECURE DESERIALIZATION VULNERABILITY SUMMARY")
        print("="*80)
        print(f"Total files with vulnerabilities: {total_count}")
        print(f"  - torch.load with weights_only=False: {len(total_vulnerabilities['torch_load_unsafe'])}")
        print(f"  - pickle.load usage: {len(total_vulnerabilities['pickle_load'])}")
        print(f"  - pickle.loads usage: {len(total_vulnerabilities['pickle_loads'])}")
        print("="*80)
        
        # Assert that vulnerabilities exist
        assert total_count > 0, (
            "Expected to find insecure deserialization vulnerabilities, but none were detected. "
            "The CVE-001 may have been addressed."
        )
    
    def test_safe_deserialization_alternatives_not_used(self):
        """
        Test: Verify that safe deserialization alternatives are not consistently used
        
        This test checks whether the codebase consistently uses safe alternatives like
        torch.load with weights_only=True.
        
        Expected: This test should FAIL (or find issues), indicating unsafe patterns are present.
        """
        # Count safe vs unsafe patterns
        safe_torch_load = 0
        unsafe_torch_load = 0
        
        nemo_dir = WORKSPACE_ROOT / 'nemo'
        if nemo_dir.exists():
            python_files = find_python_files(nemo_dir)
            
            for py_file in python_files:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Count safe torch.load (with weights_only=True)
                safe_torch_load += len(re.findall(r'torch\.load\([^)]*weights_only=True', content))
                
                # Count unsafe torch.load (with weights_only=False)
                unsafe_torch_load += len(re.findall(r'torch\.load\([^)]*weights_only=False', content))
        
        print(f"\n[CVE-001] Safe vs Unsafe torch.load patterns:")
        print(f"  - Safe (weights_only=True): {safe_torch_load}")
        print(f"  - Unsafe (weights_only=False): {unsafe_torch_load}")
        
        # Assert that unsafe patterns exist
        assert unsafe_torch_load > 0, (
            "Expected to find unsafe torch.load patterns with weights_only=False, "
            "but none were detected. The vulnerability may have been patched."
        )
        
        # Optionally check the ratio
        if safe_torch_load > 0:
            unsafe_ratio = unsafe_torch_load / (safe_torch_load + unsafe_torch_load)
            print(f"  - Unsafe ratio: {unsafe_ratio:.2%}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
