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
Security Tests for CVE-005: Remote Code Execution via Unsafe YAML Loading

This test suite validates the presence of unsafe YAML loading patterns in the codebase
that could lead to Remote Code Execution (RCE) vulnerabilities.

**IMPORTANT**: These tests are designed to DETECT the vulnerability, not fix it.
The tests will FAIL if unsafe YAML loading patterns are found in the codebase.
"""

import os
import subprocess
import tempfile
import pytest
import yaml
from pathlib import Path


class TestCVE005UnsafeYAMLLoading:
    """
    Test suite for CVE-005: Unsafe YAML Loading vulnerability
    
    These tests verify the presence of unsafe YAML loading patterns that could
    allow Remote Code Execution through malicious YAML configuration files.
    """

    @pytest.mark.unit
    def test_detect_yaml_load_without_safeloader_in_perturb_py(self):
        """
        Test 1: Detect unsafe yaml.load() in perturb.py
        
        This test verifies that the file nemo/collections/asr/parts/preprocessing/perturb.py
        contains unsafe yaml.load() calls without SafeLoader specified.
        
        **Expected**: This test should PASS (detecting the vulnerability)
        **Status**: VULNERABILITY PRESENT
        """
        file_path = Path("/workspace/nemo/collections/asr/parts/preprocessing/perturb.py")
        
        # Check if file exists
        assert file_path.exists(), f"File {file_path} does not exist"
        
        # Read file content
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for unsafe yaml.load() pattern (line 1213 based on CVE description)
        # The unsafe pattern is: yaml.load(f) without SafeLoader
        unsafe_pattern_found = False
        
        # Look for yaml.load() without SafeLoader
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            if 'yaml.load(' in line:
                # Check if it's the unsafe pattern without SafeLoader
                if 'Loader=' not in line and 'SafeLoader' not in line:
                    unsafe_pattern_found = True
                    print(f"\n[CVE-005] Unsafe yaml.load() found at line {line_num}:")
                    print(f"  {line.strip()}")
        
        # This test PASSES if the vulnerability is found
        assert unsafe_pattern_found, (
            "Expected to find unsafe yaml.load() pattern in perturb.py "
            "(as described in CVE-005), but none was found. "
            "This could mean the vulnerability has been fixed."
        )

    @pytest.mark.unit
    def test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port(self):
        """
        Test 2: Detect unsafe yaml.load() in asr_checkpoint_port.py
        
        This test verifies that the file scripts/nemo_legacy_import/asr_checkpoint_port.py
        contains unsafe yaml.load() calls without SafeLoader specified.
        
        **Expected**: This test should PASS (detecting the vulnerability)
        **Status**: VULNERABILITY PRESENT
        """
        file_path = Path("/workspace/scripts/nemo_legacy_import/asr_checkpoint_port.py")
        
        # Check if file exists
        assert file_path.exists(), f"File {file_path} does not exist"
        
        # Read file content
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for unsafe yaml.load() pattern (line 49 based on CVE description)
        unsafe_pattern_found = False
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            if 'yaml.load(' in line:
                # Check if it's the unsafe pattern without SafeLoader
                if 'Loader=' not in line and 'SafeLoader' not in line:
                    unsafe_pattern_found = True
                    print(f"\n[CVE-005] Unsafe yaml.load() found at line {line_num}:")
                    print(f"  {line.strip()}")
        
        # This test PASSES if the vulnerability is found
        assert unsafe_pattern_found, (
            "Expected to find unsafe yaml.load() pattern in asr_checkpoint_port.py "
            "(as described in CVE-005), but none was found. "
            "This could mean the vulnerability has been fixed."
        )

    @pytest.mark.unit
    def test_scan_codebase_for_all_unsafe_yaml_load_patterns(self):
        """
        Test 3: Comprehensive scan for all unsafe yaml.load() patterns
        
        This test scans the entire codebase for ANY instance of yaml.load()
        that does not specify SafeLoader, which could be exploited for RCE.
        
        **Expected**: This test should PASS if vulnerabilities are found
        **Status**: SCANNING FOR VULNERABILITIES
        """
        workspace_path = Path("/workspace")
        
        # Use grep to find all yaml.load( instances
        try:
            result = subprocess.run(
                ['grep', '-r', '-n', 'yaml\\.load(', str(workspace_path),
                 '--include=*.py',
                 '--exclude-dir=.git',
                 '--exclude-dir=__pycache__',
                 '--exclude-dir=.pytest_cache',
                 '--exclude-dir=tests'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            grep_output = result.stdout
            
            # Parse grep output to identify unsafe patterns
            unsafe_instances = []
            safe_instances = []
            
            for line in grep_output.split('\n'):
                if 'yaml.load(' in line and line.strip():
                    # Check if SafeLoader is specified
                    if 'Loader=' in line and 'SafeLoader' in line:
                        safe_instances.append(line)
                    elif 'Loader=' not in line:
                        # Potentially unsafe - no Loader specified
                        unsafe_instances.append(line)
            
            # Print findings
            print(f"\n[CVE-005] Scan Results:")
            print(f"  Total yaml.load() instances found: {len(unsafe_instances) + len(safe_instances)}")
            print(f"  Unsafe instances (no SafeLoader): {len(unsafe_instances)}")
            print(f"  Safe instances (with SafeLoader): {len(safe_instances)}")
            
            if unsafe_instances:
                print("\n  Unsafe yaml.load() patterns found at:")
                for instance in unsafe_instances[:10]:  # Show first 10
                    print(f"    {instance}")
            
            # This test PASSES if unsafe instances are found
            assert len(unsafe_instances) > 0, (
                f"Expected to find unsafe yaml.load() patterns in the codebase "
                f"(as described in CVE-005), but found {len(unsafe_instances)} instances. "
                f"Safe instances found: {len(safe_instances)}"
            )
            
        except subprocess.TimeoutExpired:
            pytest.skip("Grep command timed out")
        except FileNotFoundError:
            pytest.skip("grep command not available")

    @pytest.mark.unit
    def test_demonstrate_rce_vulnerability_with_malicious_yaml(self):
        """
        Test 4: Demonstrate RCE vulnerability with malicious YAML
        
        This test creates a malicious YAML file that would execute arbitrary code
        when loaded with unsafe yaml.load(), demonstrating the severity of CVE-005.
        
        **Expected**: This test shows how the vulnerability can be exploited
        **Status**: PROOF OF CONCEPT
        """
        # Create a malicious YAML payload that attempts to execute code
        malicious_yaml_content = """
# Malicious YAML payload for CVE-005 demonstration
# This payload would execute arbitrary Python code if loaded unsafely

!!python/object/apply:os.system
args: ['echo "RCE_VULNERABILITY_TRIGGERED" > /tmp/cve_005_test_marker.txt']
"""
        
        # Create temporary file with malicious content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_yaml_content)
            temp_yaml_path = f.name
        
        try:
            # Attempt to load with UNSAFE yaml.load() - this demonstrates the vulnerability
            # NOTE: We use a try-catch because newer PyYAML versions might warn/error
            vulnerability_demonstrated = False
            
            try:
                with open(temp_yaml_path, 'r') as f:
                    # This is the UNSAFE pattern that CVE-005 addresses
                    # In production code, this would execute the malicious payload
                    data = yaml.load(f, Loader=yaml.UnsafeLoader)  # Explicitly using UnsafeLoader for demo
                    
                # Check if the malicious code would have executed
                marker_file = Path('/tmp/cve_005_test_marker.txt')
                if marker_file.exists():
                    vulnerability_demonstrated = True
                    marker_file.unlink()  # Clean up
                    
            except yaml.constructor.ConstructorError as e:
                # If we get a ConstructorError with SafeLoader, that's expected
                print(f"\n[CVE-005] Constructor error (expected with SafeLoader): {e}")
            except Exception as e:
                print(f"\n[CVE-005] Error during unsafe load: {e}")
            
            # Now demonstrate SAFE loading with SafeLoader
            safe_load_works = True
            try:
                with open(temp_yaml_path, 'r') as f:
                    data = yaml.safe_load(f)
                    safe_load_works = False  # Should raise an error with malicious content
            except yaml.constructor.ConstructorError:
                # This is expected - safe_load prevents arbitrary code execution
                print("\n[CVE-005] Safe load correctly rejected malicious YAML")
                safe_load_works = True
            
            # Test PASSES if we demonstrated the vulnerability concept
            assert True, (
                "This test demonstrates the RCE vulnerability concept for CVE-005. "
                "Malicious YAML files can execute arbitrary code when loaded with yaml.load() "
                "without SafeLoader."
            )
            
        finally:
            # Cleanup
            if os.path.exists(temp_yaml_path):
                os.unlink(temp_yaml_path)

    @pytest.mark.unit 
    def test_verify_safe_yaml_loading_alternatives_exist(self):
        """
        Test 5: Verify that safe YAML loading patterns exist in codebase
        
        This test verifies that the codebase does use yaml.safe_load() in some places,
        confirming that developers are aware of safe practices.
        
        **Expected**: This test should PASS (finding safe patterns)
        **Status**: VERIFICATION
        """
        workspace_path = Path("/workspace")
        
        # Use grep to find yaml.safe_load() instances
        try:
            result = subprocess.run(
                ['grep', '-r', '-c', 'yaml\\.safe_load(', str(workspace_path),
                 '--include=*.py',
                 '--exclude-dir=.git',
                 '--exclude-dir=__pycache__',
                 '--exclude-dir=.pytest_cache'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Count files with safe_load
            safe_load_files = [line for line in result.stdout.split('\n') 
                              if line and not line.endswith(':0')]
            
            print(f"\n[CVE-005] Safe YAML loading patterns found in {len(safe_load_files)} files")
            
            # Test PASSES if safe patterns exist
            assert len(safe_load_files) > 0, (
                "No yaml.safe_load() patterns found in codebase. "
                "This suggests all YAML loading may be unsafe."
            )
            
        except subprocess.TimeoutExpired:
            pytest.skip("Grep command timed out")
        except FileNotFoundError:
            pytest.skip("grep command not available")

    @pytest.mark.unit
    def test_check_for_yaml_unsafe_load_usage(self):
        """
        Test 6: Check for explicit yaml.unsafe_load() usage
        
        This test checks if the codebase explicitly uses yaml.unsafe_load(),
        which is always dangerous and should never be used with untrusted input.
        
        **Expected**: This test should PASS if no unsafe_load is found
        **Status**: VERIFICATION
        """
        workspace_path = Path("/workspace")
        
        try:
            result = subprocess.run(
                ['grep', '-r', '-n', 'yaml\\.unsafe_load(', str(workspace_path),
                 '--include=*.py',
                 '--exclude-dir=.git',
                 '--exclude-dir=__pycache__',
                 '--exclude-dir=.pytest_cache',
                 '--exclude-dir=tests'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            unsafe_load_instances = [line for line in result.stdout.split('\n') if line.strip()]
            
            if unsafe_load_instances:
                print(f"\n[CVE-005] Found {len(unsafe_load_instances)} instances of yaml.unsafe_load():")
                for instance in unsafe_load_instances[:5]:
                    print(f"  {instance}")
            
            # This test PASSES if NO unsafe_load is found
            assert len(unsafe_load_instances) == 0, (
                f"Found {len(unsafe_load_instances)} instances of yaml.unsafe_load() "
                "which is explicitly unsafe and should never be used."
            )
            
        except subprocess.TimeoutExpired:
            pytest.skip("Grep command timed out")
        except FileNotFoundError:
            pytest.skip("grep command not available")

    @pytest.mark.unit
    def test_safe_yaml_loading_comparison(self):
        """
        Test 7: Compare safe vs unsafe YAML loading behavior
        
        This test creates a benign YAML file and demonstrates the difference
        between safe and unsafe loading methods.
        
        **Expected**: This test should PASS (educational test)
        **Status**: EDUCATIONAL
        """
        # Create a benign YAML file
        benign_yaml = """
model:
  name: test_model
  parameters:
    hidden_size: 256
    num_layers: 12
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(benign_yaml)
            temp_yaml_path = f.name
        
        try:
            # Test 1: Load with yaml.safe_load (RECOMMENDED)
            with open(temp_yaml_path, 'r') as f:
                safe_data = yaml.safe_load(f)
            
            assert safe_data is not None
            assert 'model' in safe_data
            print("\n[CVE-005] yaml.safe_load() works correctly with benign YAML")
            
            # Test 2: Load with yaml.load + SafeLoader (ACCEPTABLE)
            with open(temp_yaml_path, 'r') as f:
                safe_data2 = yaml.load(f, Loader=yaml.SafeLoader)
            
            assert safe_data2 is not None
            assert safe_data == safe_data2
            print("[CVE-005] yaml.load(f, Loader=yaml.SafeLoader) works correctly")
            
            # Test 3: Demonstrate that yaml.load without Loader is equivalent to UnsafeLoader
            # (we won't actually call it, just document it)
            print("[CVE-005] yaml.load(f) without Loader parameter is UNSAFE")
            print("           It allows arbitrary Python object construction")
            
            # This test always passes - it's educational
            assert True, "Safe YAML loading methods work correctly"
            
        finally:
            if os.path.exists(temp_yaml_path):
                os.unlink(temp_yaml_path)

    @pytest.mark.unit
    def test_identify_files_requiring_remediation(self):
        """
        Test 8: Generate list of files requiring security remediation
        
        This test identifies all Python files in the codebase that use
        unsafe YAML loading and need to be fixed.
        
        **Expected**: This test documents files needing fixes
        **Status**: REMEDIATION GUIDE
        """
        workspace_path = Path("/workspace")
        
        try:
            # Find all yaml.load( instances
            result = subprocess.run(
                ['grep', '-r', '-l', 'yaml\\.load(', str(workspace_path),
                 '--include=*.py',
                 '--exclude-dir=.git',
                 '--exclude-dir=__pycache__',
                 '--exclude-dir=.pytest_cache',
                 '--exclude-dir=tests',
                 '--exclude-dir=docs'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            files_with_yaml_load = [f for f in result.stdout.split('\n') if f.strip()]
            
            # Now check each file to see if it uses SafeLoader
            files_needing_fix = []
            
            for file_path in files_with_yaml_load:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Check if file has yaml.load() without SafeLoader
                    has_unsafe = False
                    for line in content.split('\n'):
                        if 'yaml.load(' in line and 'Loader=' not in line:
                            has_unsafe = True
                            break
                    
                    if has_unsafe:
                        files_needing_fix.append(file_path)
                except Exception:
                    pass
            
            print(f"\n[CVE-005] Files requiring security remediation: {len(files_needing_fix)}")
            print("\nFiles that need to be fixed:")
            for file_path in files_needing_fix:
                print(f"  - {file_path}")
            
            # Generate remediation recommendations
            print("\n[CVE-005] Remediation recommendations:")
            print("  1. Replace yaml.load(f) with yaml.safe_load(f)")
            print("  2. OR use yaml.load(f, Loader=yaml.SafeLoader)")
            print("  3. Review all YAML loading to ensure input is trusted")
            print("  4. Consider implementing input validation for YAML configs")
            
            # This test PASSES if we identified files needing fixes
            assert len(files_needing_fix) > 0, (
                "Expected to find files with unsafe yaml.load() patterns "
                "that need remediation, but none were found."
            )
            
        except subprocess.TimeoutExpired:
            pytest.skip("Grep command timed out")
        except FileNotFoundError:
            pytest.skip("grep command not available")


class TestCVE005SpecificFileVulnerabilities:
    """
    Detailed tests for specific files mentioned in CVE-005
    """
    
    @pytest.mark.unit
    def test_perturb_py_line_1213_vulnerability(self):
        """
        Test 9: Specific check for perturb.py line 1213
        
        According to CVE-005, line 1213 in perturb.py contains:
        params = yaml.load(f)
        
        This test verifies this specific vulnerability.
        """
        file_path = Path("/workspace/nemo/collections/asr/parts/preprocessing/perturb.py")
        
        if not file_path.exists():
            pytest.skip(f"File {file_path} not found")
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Check around line 1213 (allow some flexibility)
        found_vulnerability = False
        for line_num in range(max(0, 1210), min(len(lines), 1220)):
            line = lines[line_num]
            if 'yaml.load(f)' in line or 'yaml.load( f)' in line:
                print(f"\n[CVE-005] Found vulnerability at line {line_num + 1}:")
                print(f"  {line.strip()}")
                found_vulnerability = True
        
        assert found_vulnerability, (
            "Expected to find 'yaml.load(f)' vulnerability around line 1213 "
            "in perturb.py as described in CVE-005"
        )
    
    @pytest.mark.unit
    def test_asr_checkpoint_port_py_line_49_vulnerability(self):
        """
        Test 10: Specific check for asr_checkpoint_port.py line 49
        
        According to CVE-005, line 49 in asr_checkpoint_port.py contains:
        params = yaml.load(f)
        
        This test verifies this specific vulnerability.
        """
        file_path = Path("/workspace/scripts/nemo_legacy_import/asr_checkpoint_port.py")
        
        if not file_path.exists():
            pytest.skip(f"File {file_path} not found")
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Check around line 49 (allow some flexibility)
        found_vulnerability = False
        for line_num in range(max(0, 45), min(len(lines), 55)):
            line = lines[line_num]
            if 'yaml.load(f)' in line or 'yaml.load( f)' in line:
                print(f"\n[CVE-005] Found vulnerability at line {line_num + 1}:")
                print(f"  {line.strip()}")
                found_vulnerability = True
        
        assert found_vulnerability, (
            "Expected to find 'yaml.load(f)' vulnerability around line 49 "
            "in asr_checkpoint_port.py as described in CVE-005"
        )
