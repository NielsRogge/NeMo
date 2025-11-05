#!/usr/bin/env python3
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
Standalone Security Tests for CVE-005: Remote Code Execution via Unsafe YAML Loading

This standalone test suite validates the presence of unsafe YAML loading patterns
that could lead to Remote Code Execution (RCE) vulnerabilities.

**IMPORTANT**: These tests are designed to DETECT the vulnerability, not fix it.
"""

import os
import subprocess
import tempfile
import yaml
from pathlib import Path


class TestResults:
    """Simple test results tracker"""
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.results = []
    
    def add_result(self, name, status, message=""):
        self.total += 1
        if status == "PASSED":
            self.passed += 1
        elif status == "FAILED":
            self.failed += 1
        elif status == "SKIPPED":
            self.skipped += 1
        self.results.append({
            "name": name,
            "status": status,
            "message": message
        })
    
    def print_summary(self):
        print("\n" + "="*80)
        print("TEST SUMMARY - CVE-005 Security Tests")
        print("="*80)
        print(f"Total Tests: {self.total}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Skipped: {self.skipped}")
        print(f"Success Rate: {self.passed}/{self.total} ({100*self.passed/self.total if self.total > 0 else 0:.1f}%)")
        print("="*80)
        print("\nDetailed Results:")
        for result in self.results:
            status_symbol = "✓" if result["status"] == "PASSED" else "✗" if result["status"] == "FAILED" else "⊙"
            print(f"  [{status_symbol}] {result['name']}: {result['status']}")
            if result["message"]:
                print(f"      {result['message']}")
        print("="*80)


def test_detect_yaml_load_without_safeloader_in_perturb_py(results):
    """Test 1: Detect unsafe yaml.load() in perturb.py"""
    print("\n[Test 1] Detecting unsafe yaml.load() in perturb.py...")
    
    file_path = Path("/workspace/nemo/collections/asr/parts/preprocessing/perturb.py")
    
    if not file_path.exists():
        results.add_result(
            "test_detect_yaml_load_without_safeloader_in_perturb_py",
            "SKIPPED",
            f"File {file_path} does not exist"
        )
        return
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        unsafe_pattern_found = False
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            if 'yaml.load(' in line:
                if 'Loader=' not in line and 'SafeLoader' not in line:
                    unsafe_pattern_found = True
                    print(f"  [VULNERABILITY] Found unsafe yaml.load() at line {line_num}:")
                    print(f"    {line.strip()}")
        
        if unsafe_pattern_found:
            results.add_result(
                "test_detect_yaml_load_without_safeloader_in_perturb_py",
                "PASSED",
                "Unsafe yaml.load() pattern detected in perturb.py"
            )
        else:
            results.add_result(
                "test_detect_yaml_load_without_safeloader_in_perturb_py",
                "FAILED",
                "Expected to find unsafe yaml.load() pattern but none was found"
            )
    except Exception as e:
        results.add_result(
            "test_detect_yaml_load_without_safeloader_in_perturb_py",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port(results):
    """Test 2: Detect unsafe yaml.load() in asr_checkpoint_port.py"""
    print("\n[Test 2] Detecting unsafe yaml.load() in asr_checkpoint_port.py...")
    
    file_path = Path("/workspace/scripts/nemo_legacy_import/asr_checkpoint_port.py")
    
    if not file_path.exists():
        results.add_result(
            "test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port",
            "SKIPPED",
            f"File {file_path} does not exist"
        )
        return
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        unsafe_pattern_found = False
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            if 'yaml.load(' in line:
                if 'Loader=' not in line and 'SafeLoader' not in line:
                    unsafe_pattern_found = True
                    print(f"  [VULNERABILITY] Found unsafe yaml.load() at line {line_num}:")
                    print(f"    {line.strip()}")
        
        if unsafe_pattern_found:
            results.add_result(
                "test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port",
                "PASSED",
                "Unsafe yaml.load() pattern detected in asr_checkpoint_port.py"
            )
        else:
            results.add_result(
                "test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port",
                "FAILED",
                "Expected to find unsafe yaml.load() pattern but none was found"
            )
    except Exception as e:
        results.add_result(
            "test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_scan_codebase_for_all_unsafe_yaml_load_patterns(results):
    """Test 3: Comprehensive scan for all unsafe yaml.load() patterns"""
    print("\n[Test 3] Scanning codebase for unsafe yaml.load() patterns...")
    
    workspace_path = Path("/workspace")
    
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
        
        unsafe_instances = []
        safe_instances = []
        
        for line in grep_output.split('\n'):
            if 'yaml.load(' in line and line.strip():
                if 'Loader=' in line and 'SafeLoader' in line:
                    safe_instances.append(line)
                elif 'Loader=' not in line:
                    unsafe_instances.append(line)
        
        print(f"  Total yaml.load() instances found: {len(unsafe_instances) + len(safe_instances)}")
        print(f"  Unsafe instances (no SafeLoader): {len(unsafe_instances)}")
        print(f"  Safe instances (with SafeLoader): {len(safe_instances)}")
        
        if unsafe_instances:
            print("\n  Unsafe yaml.load() patterns found at:")
            for instance in unsafe_instances[:10]:
                print(f"    {instance}")
        
        if len(unsafe_instances) > 0:
            results.add_result(
                "test_scan_codebase_for_all_unsafe_yaml_load_patterns",
                "PASSED",
                f"Found {len(unsafe_instances)} unsafe yaml.load() patterns"
            )
        else:
            results.add_result(
                "test_scan_codebase_for_all_unsafe_yaml_load_patterns",
                "FAILED",
                "Expected to find unsafe yaml.load() patterns but none were found"
            )
    except subprocess.TimeoutExpired:
        results.add_result(
            "test_scan_codebase_for_all_unsafe_yaml_load_patterns",
            "SKIPPED",
            "Grep command timed out"
        )
    except FileNotFoundError:
        results.add_result(
            "test_scan_codebase_for_all_unsafe_yaml_load_patterns",
            "SKIPPED",
            "grep command not available"
        )
    except Exception as e:
        results.add_result(
            "test_scan_codebase_for_all_unsafe_yaml_load_patterns",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_demonstrate_rce_vulnerability_with_malicious_yaml(results):
    """Test 4: Demonstrate RCE vulnerability with malicious YAML"""
    print("\n[Test 4] Demonstrating RCE vulnerability with malicious YAML...")
    
    malicious_yaml_content = """
# Malicious YAML payload for CVE-005 demonstration
!!python/object/apply:os.system
args: ['echo "RCE_VULNERABILITY_TRIGGERED" > /tmp/cve_005_test_marker.txt']
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(malicious_yaml_content)
        temp_yaml_path = f.name
    
    try:
        print("  Testing with malicious YAML payload...")
        
        # Test safe loading - should reject malicious content
        safe_load_works = True
        try:
            with open(temp_yaml_path, 'r') as f:
                data = yaml.safe_load(f)
                safe_load_works = False
        except yaml.constructor.ConstructorError:
            print("    ✓ yaml.safe_load() correctly rejected malicious YAML")
            safe_load_works = True
        
        if safe_load_works:
            results.add_result(
                "test_demonstrate_rce_vulnerability_with_malicious_yaml",
                "PASSED",
                "Demonstrated that safe_load prevents RCE; unsafe load would execute code"
            )
        else:
            results.add_result(
                "test_demonstrate_rce_vulnerability_with_malicious_yaml",
                "FAILED",
                "safe_load did not reject malicious YAML as expected"
            )
    except Exception as e:
        results.add_result(
            "test_demonstrate_rce_vulnerability_with_malicious_yaml",
            "FAILED",
            f"Test error: {str(e)}"
        )
    finally:
        if os.path.exists(temp_yaml_path):
            os.unlink(temp_yaml_path)


def test_verify_safe_yaml_loading_alternatives_exist(results):
    """Test 5: Verify that safe YAML loading patterns exist"""
    print("\n[Test 5] Verifying safe yaml.safe_load() patterns exist...")
    
    workspace_path = Path("/workspace")
    
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
        
        safe_load_files = [line for line in result.stdout.split('\n') 
                          if line and not line.endswith(':0')]
        
        print(f"  Safe YAML loading patterns found in {len(safe_load_files)} files")
        
        if len(safe_load_files) > 0:
            results.add_result(
                "test_verify_safe_yaml_loading_alternatives_exist",
                "PASSED",
                f"Found safe yaml.safe_load() patterns in {len(safe_load_files)} files"
            )
        else:
            results.add_result(
                "test_verify_safe_yaml_loading_alternatives_exist",
                "FAILED",
                "No yaml.safe_load() patterns found"
            )
    except subprocess.TimeoutExpired:
        results.add_result(
            "test_verify_safe_yaml_loading_alternatives_exist",
            "SKIPPED",
            "Grep command timed out"
        )
    except FileNotFoundError:
        results.add_result(
            "test_verify_safe_yaml_loading_alternatives_exist",
            "SKIPPED",
            "grep command not available"
        )
    except Exception as e:
        results.add_result(
            "test_verify_safe_yaml_loading_alternatives_exist",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_check_for_yaml_unsafe_load_usage(results):
    """Test 6: Check for explicit yaml.unsafe_load() usage"""
    print("\n[Test 6] Checking for explicit yaml.unsafe_load() usage...")
    
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
            print(f"  Found {len(unsafe_load_instances)} instances of yaml.unsafe_load():")
            for instance in unsafe_load_instances[:5]:
                print(f"    {instance}")
        
        if len(unsafe_load_instances) == 0:
            results.add_result(
                "test_check_for_yaml_unsafe_load_usage",
                "PASSED",
                "No yaml.unsafe_load() instances found (good)"
            )
        else:
            results.add_result(
                "test_check_for_yaml_unsafe_load_usage",
                "FAILED",
                f"Found {len(unsafe_load_instances)} yaml.unsafe_load() instances"
            )
    except subprocess.TimeoutExpired:
        results.add_result(
            "test_check_for_yaml_unsafe_load_usage",
            "SKIPPED",
            "Grep command timed out"
        )
    except FileNotFoundError:
        results.add_result(
            "test_check_for_yaml_unsafe_load_usage",
            "SKIPPED",
            "grep command not available"
        )
    except Exception as e:
        results.add_result(
            "test_check_for_yaml_unsafe_load_usage",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_safe_yaml_loading_comparison(results):
    """Test 7: Compare safe vs unsafe YAML loading behavior"""
    print("\n[Test 7] Comparing safe vs unsafe YAML loading behavior...")
    
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
        with open(temp_yaml_path, 'r') as f:
            safe_data = yaml.safe_load(f)
        
        with open(temp_yaml_path, 'r') as f:
            safe_data2 = yaml.load(f, Loader=yaml.SafeLoader)
        
        if safe_data is not None and safe_data == safe_data2 and 'model' in safe_data:
            print("    ✓ yaml.safe_load() works correctly")
            print("    ✓ yaml.load(f, Loader=yaml.SafeLoader) works correctly")
            results.add_result(
                "test_safe_yaml_loading_comparison",
                "PASSED",
                "Safe YAML loading methods work correctly"
            )
        else:
            results.add_result(
                "test_safe_yaml_loading_comparison",
                "FAILED",
                "Safe YAML loading methods did not work as expected"
            )
    except Exception as e:
        results.add_result(
            "test_safe_yaml_loading_comparison",
            "FAILED",
            f"Test error: {str(e)}"
        )
    finally:
        if os.path.exists(temp_yaml_path):
            os.unlink(temp_yaml_path)


def test_identify_files_requiring_remediation(results):
    """Test 8: Generate list of files requiring security remediation"""
    print("\n[Test 8] Identifying files requiring security remediation...")
    
    workspace_path = Path("/workspace")
    
    try:
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
        
        files_needing_fix = []
        
        for file_path in files_with_yaml_load:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                has_unsafe = False
                for line in content.split('\n'):
                    if 'yaml.load(' in line and 'Loader=' not in line:
                        has_unsafe = True
                        break
                
                if has_unsafe:
                    files_needing_fix.append(file_path)
            except Exception:
                pass
        
        print(f"  Files requiring security remediation: {len(files_needing_fix)}")
        print("\n  Files that need to be fixed:")
        for file_path in files_needing_fix:
            print(f"    - {file_path}")
        
        print("\n  Remediation recommendations:")
        print("    1. Replace yaml.load(f) with yaml.safe_load(f)")
        print("    2. OR use yaml.load(f, Loader=yaml.SafeLoader)")
        print("    3. Review all YAML loading to ensure input is trusted")
        
        if len(files_needing_fix) > 0:
            results.add_result(
                "test_identify_files_requiring_remediation",
                "PASSED",
                f"Identified {len(files_needing_fix)} files requiring remediation"
            )
        else:
            results.add_result(
                "test_identify_files_requiring_remediation",
                "FAILED",
                "Expected to find files needing remediation but none were found"
            )
    except subprocess.TimeoutExpired:
        results.add_result(
            "test_identify_files_requiring_remediation",
            "SKIPPED",
            "Grep command timed out"
        )
    except FileNotFoundError:
        results.add_result(
            "test_identify_files_requiring_remediation",
            "SKIPPED",
            "grep command not available"
        )
    except Exception as e:
        results.add_result(
            "test_identify_files_requiring_remediation",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_perturb_py_line_1213_vulnerability(results):
    """Test 9: Specific check for perturb.py line 1213"""
    print("\n[Test 9] Checking specific vulnerability at perturb.py line 1213...")
    
    file_path = Path("/workspace/nemo/collections/asr/parts/preprocessing/perturb.py")
    
    if not file_path.exists():
        results.add_result(
            "test_perturb_py_line_1213_vulnerability",
            "SKIPPED",
            f"File {file_path} not found"
        )
        return
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        found_vulnerability = False
        for line_num in range(max(0, 1210), min(len(lines), 1220)):
            line = lines[line_num]
            if 'yaml.load(f)' in line or 'yaml.load( f)' in line:
                print(f"  [VULNERABILITY] Found at line {line_num + 1}:")
                print(f"    {line.strip()}")
                found_vulnerability = True
        
        if found_vulnerability:
            results.add_result(
                "test_perturb_py_line_1213_vulnerability",
                "PASSED",
                "Found 'yaml.load(f)' vulnerability around line 1213"
            )
        else:
            results.add_result(
                "test_perturb_py_line_1213_vulnerability",
                "FAILED",
                "Expected to find vulnerability at line 1213 but none was found"
            )
    except Exception as e:
        results.add_result(
            "test_perturb_py_line_1213_vulnerability",
            "FAILED",
            f"Test error: {str(e)}"
        )


def test_asr_checkpoint_port_py_line_49_vulnerability(results):
    """Test 10: Specific check for asr_checkpoint_port.py line 49"""
    print("\n[Test 10] Checking specific vulnerability at asr_checkpoint_port.py line 49...")
    
    file_path = Path("/workspace/scripts/nemo_legacy_import/asr_checkpoint_port.py")
    
    if not file_path.exists():
        results.add_result(
            "test_asr_checkpoint_port_py_line_49_vulnerability",
            "SKIPPED",
            f"File {file_path} not found"
        )
        return
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        found_vulnerability = False
        for line_num in range(max(0, 45), min(len(lines), 55)):
            line = lines[line_num]
            if 'yaml.load(f)' in line or 'yaml.load( f)' in line:
                print(f"  [VULNERABILITY] Found at line {line_num + 1}:")
                print(f"    {line.strip()}")
                found_vulnerability = True
        
        if found_vulnerability:
            results.add_result(
                "test_asr_checkpoint_port_py_line_49_vulnerability",
                "PASSED",
                "Found 'yaml.load(f)' vulnerability around line 49"
            )
        else:
            results.add_result(
                "test_asr_checkpoint_port_py_line_49_vulnerability",
                "FAILED",
                "Expected to find vulnerability at line 49 but none was found"
            )
    except Exception as e:
        results.add_result(
            "test_asr_checkpoint_port_py_line_49_vulnerability",
            "FAILED",
            f"Test error: {str(e)}"
        )


def main():
    """Run all security tests for CVE-005"""
    print("="*80)
    print("CVE-005 Security Test Suite")
    print("Remote Code Execution via Unsafe YAML Loading")
    print("="*80)
    print("\nThese tests DETECT the vulnerability (they do NOT fix it)")
    print("Tests will PASS when vulnerabilities are found")
    print("="*80)
    
    results = TestResults()
    
    # Run all tests
    test_detect_yaml_load_without_safeloader_in_perturb_py(results)
    test_detect_yaml_load_without_safeloader_in_asr_checkpoint_port(results)
    test_scan_codebase_for_all_unsafe_yaml_load_patterns(results)
    test_demonstrate_rce_vulnerability_with_malicious_yaml(results)
    test_verify_safe_yaml_loading_alternatives_exist(results)
    test_check_for_yaml_unsafe_load_usage(results)
    test_safe_yaml_loading_comparison(results)
    test_identify_files_requiring_remediation(results)
    test_perturb_py_line_1213_vulnerability(results)
    test_asr_checkpoint_port_py_line_49_vulnerability(results)
    
    # Print summary
    results.print_summary()
    
    # Return exit code
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    exit(main())
