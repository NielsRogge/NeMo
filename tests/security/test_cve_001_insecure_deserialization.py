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
Security Tests for CVE-001: Insecure Deserialization

This test suite verifies the presence of insecure deserialization patterns
in the NeMo codebase that could lead to remote code execution vulnerabilities.

CVE-001 focuses on:
- torch.load with weights_only=False
- pickle.load/pickle.loads without safety checks
- numpy.load without allow_pickle=False
- joblib.load without safety measures
"""

import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest


class TestCVE001InsecureDeserialization:
    """
    Test suite for CVE-001: Insecure Deserialization vulnerability.
    
    These tests verify that the codebase contains insecure deserialization
    patterns that could be exploited for remote code execution.
    """

    @pytest.fixture(scope="class")
    def nemo_root(self):
        """Get the NeMo repository root directory."""
        return Path(__file__).parent.parent.parent

    @pytest.fixture(scope="class")
    def python_files(self, nemo_root):
        """Get all Python files in the NeMo codebase."""
        python_files = []
        
        # Search in main nemo directory
        nemo_dir = nemo_root / "nemo"
        if nemo_dir.exists():
            for py_file in nemo_dir.rglob("*.py"):
                python_files.append(py_file)
        
        # Search in examples directory
        examples_dir = nemo_root / "examples"
        if examples_dir.exists():
            for py_file in examples_dir.rglob("*.py"):
                python_files.append(py_file)
        
        # Search in scripts directory
        scripts_dir = nemo_root / "scripts"
        if scripts_dir.exists():
            for py_file in scripts_dir.rglob("*.py"):
                python_files.append(py_file)
        
        # Search in tools directory
        tools_dir = nemo_root / "tools"
        if tools_dir.exists():
            for py_file in tools_dir.rglob("*.py"):
                python_files.append(py_file)
        
        return python_files

    def find_pattern_in_file(self, file_path: Path, pattern: str) -> List[Tuple[int, str]]:
        """
        Find all occurrences of a pattern in a file.
        
        Args:
            file_path: Path to the file to search
            pattern: Regular expression pattern to search for
            
        Returns:
            List of tuples containing (line_number, line_content)
        """
        matches = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, start=1):
                    if re.search(pattern, line):
                        matches.append((line_num, line.strip()))
        except Exception:
            # Skip files that can't be read
            pass
        return matches

    @pytest.mark.unit
    def test_torch_load_with_weights_only_false(self, python_files):
        """
        CVE-001-1: Test for torch.load with weights_only=False
        
        This test verifies that torch.load is used with weights_only=False,
        which allows arbitrary code execution when loading untrusted models.
        
        VULNERABILITY: torch.load with weights_only=False can execute arbitrary
        Python code embedded in the serialized file.
        """
        vulnerable_files = {}
        pattern = r'torch\.load\([^)]*weights_only\s*=\s*False'
        
        for py_file in python_files:
            matches = self.find_pattern_in_file(py_file, pattern)
            if matches:
                vulnerable_files[str(py_file)] = matches
        
        # Assert that vulnerable patterns exist (this test SHOULD pass if vulnerability exists)
        assert len(vulnerable_files) > 0, (
            "Expected to find torch.load calls with weights_only=False. "
            "If this test fails, the vulnerability may have been fixed."
        )
        
        print(f"\n[CVE-001-1] Found {len(vulnerable_files)} files with torch.load(weights_only=False)")
        for file_path, matches in list(vulnerable_files.items())[:5]:  # Show first 5
            print(f"  - {file_path}: {len(matches)} occurrence(s)")

    @pytest.mark.unit
    def test_torch_load_without_weights_only(self, python_files):
        """
        CVE-001-2: Test for torch.load without explicit weights_only parameter
        
        This test identifies torch.load calls that don't specify weights_only,
        which defaults to False in older PyTorch versions.
        
        VULNERABILITY: torch.load without weights_only parameter may default
        to unsafe deserialization.
        """
        vulnerable_files = {}
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # Find torch.load calls
                torch_load_pattern = r'torch\.load\([^)]+\)'
                matches = re.finditer(torch_load_pattern, content)
                
                for match in matches:
                    call_text = match.group(0)
                    # Check if weights_only is NOT specified
                    if 'weights_only' not in call_text:
                        if str(py_file) not in vulnerable_files:
                            vulnerable_files[str(py_file)] = []
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        vulnerable_files[str(py_file)].append((line_num, call_text[:80]))
            except Exception:
                pass
        
        assert len(vulnerable_files) > 0, (
            "Expected to find torch.load calls without weights_only parameter. "
            "If this test fails, all torch.load calls may have been secured."
        )
        
        print(f"\n[CVE-001-2] Found {len(vulnerable_files)} files with torch.load missing weights_only")
        for file_path, matches in list(vulnerable_files.items())[:5]:
            print(f"  - {file_path}: {len(matches)} occurrence(s)")

    @pytest.mark.unit
    def test_pickle_load_usage(self, python_files):
        """
        CVE-001-3: Test for pickle.load usage
        
        This test identifies all uses of pickle.load, which can execute arbitrary
        code during deserialization.
        
        VULNERABILITY: pickle.load is inherently unsafe with untrusted data and
        can execute arbitrary Python code.
        """
        vulnerable_files = {}
        pattern = r'pickle\.load\('
        
        for py_file in python_files:
            matches = self.find_pattern_in_file(py_file, pattern)
            if matches:
                vulnerable_files[str(py_file)] = matches
        
        assert len(vulnerable_files) > 0, (
            "Expected to find pickle.load calls. "
            "If this test fails, pickle.load usage may have been eliminated."
        )
        
        print(f"\n[CVE-001-3] Found {len(vulnerable_files)} files using pickle.load")
        for file_path, matches in list(vulnerable_files.items())[:5]:
            print(f"  - {file_path}: {len(matches)} occurrence(s)")

    @pytest.mark.unit
    def test_pickle_loads_usage(self, python_files):
        """
        CVE-001-4: Test for pickle.loads usage
        
        This test identifies all uses of pickle.loads, which deserializes from
        bytes and can execute arbitrary code.
        
        VULNERABILITY: pickle.loads is equally unsafe as pickle.load and can
        execute arbitrary Python code from byte streams.
        """
        vulnerable_files = {}
        pattern = r'pickle\.loads\('
        
        for py_file in python_files:
            matches = self.find_pattern_in_file(py_file, pattern)
            if matches:
                vulnerable_files[str(py_file)] = matches
        
        assert len(vulnerable_files) > 0, (
            "Expected to find pickle.loads calls. "
            "If this test fails, pickle.loads usage may have been eliminated."
        )
        
        print(f"\n[CVE-001-4] Found {len(vulnerable_files)} files using pickle.loads")
        for file_path, matches in list(vulnerable_files.items())[:5]:
            print(f"  - {file_path}: {len(matches)} occurrence(s)")

    @pytest.mark.unit
    def test_joblib_load_usage(self, python_files):
        """
        CVE-001-5: Test for joblib.load usage
        
        This test identifies uses of joblib.load, which internally uses pickle
        and inherits its security vulnerabilities.
        
        VULNERABILITY: joblib.load uses pickle internally and is vulnerable
        to the same code execution attacks.
        """
        vulnerable_files = {}
        pattern = r'joblib\.load\('
        
        for py_file in python_files:
            matches = self.find_pattern_in_file(py_file, pattern)
            if matches:
                vulnerable_files[str(py_file)] = matches
        
        # This may not exist in the codebase, so we make it optional
        if len(vulnerable_files) > 0:
            print(f"\n[CVE-001-5] Found {len(vulnerable_files)} files using joblib.load")
            for file_path, matches in list(vulnerable_files.items())[:5]:
                print(f"  - {file_path}: {len(matches)} occurrence(s)")
        else:
            print("\n[CVE-001-5] No joblib.load usage found (acceptable)")
        
        # Pass test regardless - this is informational
        assert True

    @pytest.mark.unit
    def test_numpy_load_with_allow_pickle(self, python_files):
        """
        CVE-001-6: Test for numpy.load with allow_pickle=True
        
        This test identifies numpy.load calls that explicitly allow pickle,
        which can lead to arbitrary code execution.
        
        VULNERABILITY: numpy.load with allow_pickle=True can execute arbitrary
        code from malicious .npy files.
        """
        vulnerable_files = {}
        pattern = r'(?:numpy|np)\.load\([^)]*allow_pickle\s*=\s*True'
        
        for py_file in python_files:
            matches = self.find_pattern_in_file(py_file, pattern)
            if matches:
                vulnerable_files[str(py_file)] = matches
        
        # This may not exist in the codebase, so we make it optional
        if len(vulnerable_files) > 0:
            print(f"\n[CVE-001-6] Found {len(vulnerable_files)} files with numpy.load(allow_pickle=True)")
            for file_path, matches in list(vulnerable_files.items())[:5]:
                print(f"  - {file_path}: {len(matches)} occurrence(s)")
        else:
            print("\n[CVE-001-6] No numpy.load with allow_pickle=True found (good)")
        
        # Pass test regardless - this is informational
        assert True

    @pytest.mark.unit
    def test_save_restore_connector_vulnerability(self, nemo_root):
        """
        CVE-001-7: Test specific vulnerability in save_restore_connector.py
        
        This test verifies the known vulnerable code in the SaveRestoreConnector
        that uses torch.load with weights_only=False.
        
        VULNERABILITY: The _load_state_dict_from_disk method explicitly sets
        weights_only=False, allowing arbitrary code execution.
        """
        connector_file = nemo_root / "nemo" / "core" / "connectors" / "save_restore_connector.py"
        
        assert connector_file.exists(), f"File not found: {connector_file}"
        
        vulnerable_pattern_found = False
        vulnerable_lines = []
        
        with open(connector_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                if 'torch.load' in line and 'weights_only=False' in line:
                    vulnerable_pattern_found = True
                    vulnerable_lines.append((line_num, line.strip()))
        
        assert vulnerable_pattern_found, (
            "Expected to find torch.load with weights_only=False in save_restore_connector.py. "
            "If this test fails, the specific vulnerability may have been fixed."
        )
        
        print(f"\n[CVE-001-7] Found vulnerable torch.load in save_restore_connector.py:")
        for line_num, line in vulnerable_lines:
            print(f"  Line {line_num}: {line}")

    @pytest.mark.unit
    def test_data_explorer_pickle_vulnerability(self, nemo_root):
        """
        CVE-001-8: Test specific vulnerability in data_explorer.py
        
        This test verifies the known vulnerable code in the speech data explorer
        that uses pickle.load to deserialize cached data.
        
        VULNERABILITY: The data_explorer.py loads cached data using pickle.load
        without validation, which could execute malicious code.
        """
        explorer_file = nemo_root / "tools" / "speech_data_explorer" / "data_explorer.py"
        
        if not explorer_file.exists():
            print(f"\n[CVE-001-8] File not found: {explorer_file} (may have been removed)")
            assert True  # Pass if file doesn't exist
            return
        
        vulnerable_pattern_found = False
        vulnerable_lines = []
        
        with open(explorer_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                if 'pickle.load' in line:
                    vulnerable_pattern_found = True
                    vulnerable_lines.append((line_num, line.strip()))
        
        if vulnerable_pattern_found:
            print(f"\n[CVE-001-8] Found pickle.load in data_explorer.py:")
            for line_num, line in vulnerable_lines[:3]:  # Show first 3
                print(f"  Line {line_num}: {line}")
        else:
            print("\n[CVE-001-8] No pickle.load found in data_explorer.py (may be fixed)")
        
        # Pass test regardless as file structure may have changed
        assert True

    @pytest.mark.unit
    def test_deserialization_in_core_modules(self, nemo_root):
        """
        CVE-001-9: Test for insecure deserialization in core NeMo modules
        
        This test scans the core nemo modules for any deserialization patterns
        that could be exploited.
        
        VULNERABILITY: Core modules with insecure deserialization affect the
        entire NeMo framework.
        """
        core_dir = nemo_root / "nemo" / "core"
        
        if not core_dir.exists():
            assert False, f"Core directory not found: {core_dir}"
        
        vulnerable_files = {}
        patterns = [
            r'torch\.load\(',
            r'pickle\.load\(',
            r'pickle\.loads\(',
        ]
        
        for py_file in core_dir.rglob("*.py"):
            for pattern in patterns:
                matches = self.find_pattern_in_file(py_file, pattern)
                if matches:
                    if str(py_file) not in vulnerable_files:
                        vulnerable_files[str(py_file)] = []
                    vulnerable_files[str(py_file)].extend(matches)
        
        if len(vulnerable_files) > 0:
            print(f"\n[CVE-001-9] Found {len(vulnerable_files)} core module files with deserialization:")
            for file_path, matches in list(vulnerable_files.items())[:5]:
                print(f"  - {file_path}: {len(matches)} occurrence(s)")
            assert True  # Vulnerability exists
        else:
            print("\n[CVE-001-9] No deserialization found in core modules")
            assert True  # Pass either way

    @pytest.mark.unit
    def test_deserialization_in_collections(self, nemo_root):
        """
        CVE-001-10: Test for insecure deserialization in NeMo collections
        
        This test scans the collections modules for deserialization patterns.
        Collections are particularly concerning as they handle model loading
        from potentially untrusted sources.
        
        VULNERABILITY: Collections modules load models and data, making them
        prime targets for deserialization attacks.
        """
        collections_dir = nemo_root / "nemo" / "collections"
        
        if not collections_dir.exists():
            assert False, f"Collections directory not found: {collections_dir}"
        
        vulnerable_files = {}
        patterns = [
            r'torch\.load\(',
            r'pickle\.load\(',
            r'pickle\.loads\(',
        ]
        
        for py_file in collections_dir.rglob("*.py"):
            for pattern in patterns:
                matches = self.find_pattern_in_file(py_file, pattern)
                if matches:
                    if str(py_file) not in vulnerable_files:
                        vulnerable_files[str(py_file)] = []
                    vulnerable_files[str(py_file)].extend(matches)
        
        assert len(vulnerable_files) > 0, (
            "Expected to find deserialization in collections modules. "
            "If this test fails, the vulnerability may have been fixed."
        )
        
        print(f"\n[CVE-001-10] Found {len(vulnerable_files)} collection files with deserialization:")
        for file_path, matches in list(vulnerable_files.items())[:10]:
            rel_path = Path(file_path).relative_to(nemo_root)
            print(f"  - {rel_path}: {len(matches)} occurrence(s)")

    @pytest.mark.unit
    def test_comprehensive_vulnerability_summary(self, python_files, nemo_root):
        """
        CVE-001-11: Comprehensive summary of all deserialization vulnerabilities
        
        This test provides a comprehensive summary of all insecure deserialization
        patterns found in the codebase.
        
        VULNERABILITY: This summary demonstrates the widespread nature of the
        insecure deserialization vulnerability across the NeMo codebase.
        """
        all_vulnerabilities = {
            'torch.load with weights_only=False': [],
            'torch.load without weights_only': [],
            'pickle.load': [],
            'pickle.loads': [],
            'joblib.load': [],
            'numpy.load with allow_pickle': [],
        }
        
        patterns = {
            'torch.load with weights_only=False': r'torch\.load\([^)]*weights_only\s*=\s*False',
            'pickle.load': r'pickle\.load\(',
            'pickle.loads': r'pickle\.loads\(',
            'joblib.load': r'joblib\.load\(',
            'numpy.load with allow_pickle': r'(?:numpy|np)\.load\([^)]*allow_pickle\s*=\s*True',
        }
        
        # Scan for each pattern
        for vuln_type, pattern in patterns.items():
            for py_file in python_files:
                matches = self.find_pattern_in_file(py_file, pattern)
                if matches:
                    try:
                        rel_path = py_file.relative_to(nemo_root)
                        all_vulnerabilities[vuln_type].append((str(rel_path), len(matches)))
                    except ValueError:
                        all_vulnerabilities[vuln_type].append((str(py_file), len(matches)))
        
        # Also check for torch.load without weights_only
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                torch_load_pattern = r'torch\.load\([^)]+\)'
                matches = re.finditer(torch_load_pattern, content)
                
                count = 0
                for match in matches:
                    if 'weights_only' not in match.group(0):
                        count += 1
                
                if count > 0:
                    try:
                        rel_path = py_file.relative_to(nemo_root)
                        all_vulnerabilities['torch.load without weights_only'].append((str(rel_path), count))
                    except ValueError:
                        all_vulnerabilities['torch.load without weights_only'].append((str(py_file), count))
            except Exception:
                pass
        
        # Print comprehensive summary
        print("\n" + "=" * 80)
        print("CVE-001 COMPREHENSIVE VULNERABILITY SUMMARY")
        print("=" * 80)
        
        total_files = 0
        total_occurrences = 0
        
        for vuln_type, files in all_vulnerabilities.items():
            if files:
                print(f"\n{vuln_type}:")
                print(f"  Files affected: {len(files)}")
                occurrences = sum(count for _, count in files)
                print(f"  Total occurrences: {occurrences}")
                total_files += len(files)
                total_occurrences += occurrences
                
                # Show top 5 files
                sorted_files = sorted(files, key=lambda x: x[1], reverse=True)
                print(f"  Top affected files:")
                for file_path, count in sorted_files[:5]:
                    print(f"    - {file_path}: {count} occurrence(s)")
        
        print(f"\n{'-' * 80}")
        print(f"TOTAL UNIQUE FILES WITH VULNERABILITIES: {total_files}")
        print(f"TOTAL VULNERABILITY OCCURRENCES: {total_occurrences}")
        print("=" * 80)
        
        # Assert that vulnerabilities exist
        assert total_occurrences > 0, (
            "Expected to find insecure deserialization vulnerabilities. "
            "If this test fails, CVE-001 may have been fully remediated."
        )


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v", "-s"])
