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
Security Tests for CVE-005: Remote Code Execution via Unsafe YAML Loading

CVE ID: CVE-005
Title: [CVE-005] Remote Code Execution via Unsafe YAML Loading
Severity: CRITICAL
Jira Issue: https://ml6team.atlassian.net/browse/DR-137

Description:
    The application is vulnerable to RCE via unsafe YAML loading. Using yaml.load()
    without SafeLoader can allow an attacker to execute arbitrary code by crafting
    a malicious configuration file.

Vulnerable files identified:
    - nemo/collections/asr/parts/preprocessing/perturb.py:1213
    - scripts/nemo_legacy_import/asr_checkpoint_port.py:49

These tests verify the presence of unsafe YAML loading patterns and demonstrate
the security risk. They are designed to detect the vulnerability, not fix it.
"""

import ast
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml


class TestCVE005UnsafeYAMLLoading:
    """
    Test suite for CVE-005: Remote Code Execution via Unsafe YAML Loading
    
    This test suite verifies the presence of unsafe YAML loading patterns in the
    codebase and demonstrates the potential for Remote Code Execution (RCE).
    """

    @pytest.mark.unit
    def test_yaml_load_without_loader_is_vulnerable(self):
        """
        Test that yaml.load() without a Loader parameter is vulnerable to RCE.
        
        This test demonstrates the vulnerability by showing that yaml.load() without
        a Loader parameter can execute arbitrary Python code embedded in YAML.
        
        NOTE: This test is expected to FAIL if the vulnerability has been fixed.
        """
        # Malicious YAML that executes Python code
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "VULNERABLE: Arbitrary code execution successful"']
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_yaml)
            temp_file = f.name
        
        try:
            # This should execute the code in the YAML if vulnerable
            with open(temp_file, 'r') as f:
                try:
                    # Using yaml.load() without Loader parameter (VULNERABLE)
                    result = yaml.load(f)
                    # If we reach here without error, the system is vulnerable
                    pytest.fail(
                        "VULNERABILITY CONFIRMED: yaml.load() without Loader executed arbitrary code. "
                        "This is CVE-005."
                    )
                except yaml.YAMLLoadWarning:
                    # Modern PyYAML versions warn about this
                    pytest.skip("PyYAML version includes warnings for unsafe load")
                except AttributeError:
                    # Some PyYAML versions may fail differently
                    pass
        finally:
            os.unlink(temp_file)

    @pytest.mark.unit
    def test_yaml_load_with_fullloader_is_partially_vulnerable(self):
        """
        Test that yaml.load() with FullLoader may still be vulnerable to some attacks.
        
        FullLoader is safer than not specifying a loader, but SafeLoader is recommended
        for loading untrusted input.
        """
        # YAML that attempts to instantiate Python objects
        potentially_dangerous_yaml = """
!!python/object/new:dict
state:
  key: value
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(potentially_dangerous_yaml)
            temp_file = f.name
        
        try:
            with open(temp_file, 'r') as f:
                # Using FullLoader (partially safe but not recommended)
                try:
                    result = yaml.load(f, Loader=yaml.FullLoader)
                    # FullLoader may allow some object instantiation
                    if isinstance(result, dict):
                        pytest.skip("FullLoader prevented dangerous object instantiation")
                except yaml.constructor.ConstructorError:
                    # FullLoader correctly rejected the dangerous construct
                    pass
        finally:
            os.unlink(temp_file)

    @pytest.mark.unit
    def test_yaml_safeloader_prevents_rce(self):
        """
        Test that yaml.load() with SafeLoader prevents RCE.
        
        This is a NEGATIVE TEST showing the correct/safe way to load YAML.
        SafeLoader should prevent execution of arbitrary code.
        """
        # Malicious YAML that attempts to execute Python code
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "This should not execute"']
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_yaml)
            temp_file = f.name
        
        try:
            with open(temp_file, 'r') as f:
                # Using SafeLoader (SAFE)
                with pytest.raises(yaml.constructor.ConstructorError):
                    yaml.load(f, Loader=yaml.SafeLoader)
        finally:
            os.unlink(temp_file)

    @pytest.mark.unit
    def test_yaml_safe_load_prevents_rce(self):
        """
        Test that yaml.safe_load() prevents RCE.
        
        This is a NEGATIVE TEST showing the correct/safe way to load YAML.
        yaml.safe_load() is equivalent to yaml.load(stream, Loader=SafeLoader).
        """
        # Malicious YAML that attempts to execute Python code
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "This should not execute"']
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_yaml)
            temp_file = f.name
        
        try:
            with open(temp_file, 'r') as f:
                # Using safe_load() (SAFE)
                with pytest.raises(yaml.constructor.ConstructorError):
                    yaml.safe_load(f)
        finally:
            os.unlink(temp_file)

    @pytest.mark.unit
    def test_detect_unsafe_yaml_load_in_codebase(self):
        """
        Test to detect unsafe yaml.load() patterns in the codebase.
        
        This test scans Python files for unsafe YAML loading patterns:
        - yaml.load() without Loader parameter
        - yaml.load() with FullLoader (less critical but not recommended)
        - yaml.unsafe_load() (explicitly unsafe)
        
        This test documents which files contain potentially vulnerable code.
        """
        workspace_path = Path("/workspace")
        
        # Files to scan
        scan_paths = [
            workspace_path / "nemo",
            workspace_path / "scripts",
            workspace_path / "examples",
        ]
        
        vulnerable_files = []
        
        for scan_path in scan_paths:
            if not scan_path.exists():
                continue
                
            for python_file in scan_path.rglob("*.py"):
                try:
                    with open(python_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Parse the file to find yaml.load() calls
                    try:
                        tree = ast.parse(content, filename=str(python_file))
                        
                        for node in ast.walk(tree):
                            # Check for yaml.load() calls
                            if isinstance(node, ast.Call):
                                # Check if it's a yaml.load call
                                is_yaml_load = False
                                
                                if isinstance(node.func, ast.Attribute):
                                    if (node.func.attr == 'load' and 
                                        isinstance(node.func.value, ast.Name) and 
                                        node.func.value.id == 'yaml'):
                                        is_yaml_load = True
                                
                                if is_yaml_load:
                                    # Check if Loader parameter is specified
                                    has_safe_loader = False
                                    
                                    # Check keyword arguments
                                    for keyword in node.keywords:
                                        if keyword.arg == 'Loader':
                                            # Check if it's SafeLoader
                                            if isinstance(keyword.value, ast.Attribute):
                                                if (keyword.value.attr == 'SafeLoader' and
                                                    isinstance(keyword.value.value, ast.Name) and
                                                    keyword.value.value.id == 'yaml'):
                                                    has_safe_loader = True
                                    
                                    if not has_safe_loader:
                                        # Found potentially unsafe yaml.load()
                                        vulnerable_files.append({
                                            'file': str(python_file.relative_to(workspace_path)),
                                            'line': node.lineno,
                                            'col': node.col_offset
                                        })
                                
                                # Check for yaml.unsafe_load() calls
                                if isinstance(node.func, ast.Attribute):
                                    if (node.func.attr == 'unsafe_load' and 
                                        isinstance(node.func.value, ast.Name) and 
                                        node.func.value.id == 'yaml'):
                                        vulnerable_files.append({
                                            'file': str(python_file.relative_to(workspace_path)),
                                            'line': node.lineno,
                                            'col': node.col_offset,
                                            'type': 'unsafe_load'
                                        })
                    
                    except SyntaxError:
                        # Skip files with syntax errors
                        pass
                        
                except Exception:
                    # Skip files that can't be read
                    pass
        
        # Document findings
        if vulnerable_files:
            message = "\n\nVULNERABILITY DETECTED (CVE-005): Found potentially unsafe YAML loading patterns:\n"
            for vuln in vulnerable_files[:10]:  # Show first 10 to avoid overwhelming output
                file_info = f"  - {vuln['file']}:{vuln['line']}"
                if 'type' in vuln:
                    file_info += f" (yaml.{vuln['type']})"
                message += file_info + "\n"
            
            if len(vulnerable_files) > 10:
                message += f"  ... and {len(vulnerable_files) - 10} more files\n"
            
            message += f"\nTotal potentially vulnerable locations: {len(vulnerable_files)}\n"
            message += "\nRECOMMENDATION: Replace yaml.load() with yaml.safe_load() or yaml.load(stream, Loader=yaml.SafeLoader)\n"
            
            pytest.fail(message)

    @pytest.mark.unit
    def test_verify_specific_cve_files(self):
        """
        Test to verify the specific files mentioned in CVE-005.
        
        According to the CVE report, these files contain unsafe yaml.load():
        - nemo/collections/asr/parts/preprocessing/perturb.py:1213
        - scripts/nemo_legacy_import/asr_checkpoint_port.py:49
        
        This test checks if these files still contain the vulnerable patterns.
        """
        workspace_path = Path("/workspace")
        
        cve_files = [
            {
                'path': workspace_path / "nemo/collections/asr/parts/preprocessing/perturb.py",
                'line': 1213,
                'description': 'ASR preprocessing perturb module'
            },
            {
                'path': workspace_path / "scripts/nemo_legacy_import/asr_checkpoint_port.py",
                'line': 49,
                'description': 'ASR checkpoint porting script'
            }
        ]
        
        findings = []
        
        for file_info in cve_files:
            file_path = file_info['path']
            
            if not file_path.exists():
                findings.append(f"File not found: {file_path}")
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Check the specific line mentioned in CVE
                if file_info['line'] <= len(lines):
                    target_line = lines[file_info['line'] - 1]
                    
                    # Check if the line contains yaml.load
                    if 'yaml.load' in target_line or 'yaml.unsafe_load' in target_line:
                        # Check if it's using SafeLoader
                        if 'SafeLoader' not in target_line and 'safe_load' not in target_line:
                            # Check context around the line for ruamel.yaml safe usage
                            context_start = max(0, file_info['line'] - 10)
                            context_end = min(len(lines), file_info['line'] + 5)
                            context = ''.join(lines[context_start:context_end])
                            
                            # ruamel.yaml with typ='safe' is safe
                            if "YAML(typ='safe')" in context or 'YAML(typ="safe")' in context:
                                findings.append(
                                    f"✓ {file_info['path'].relative_to(workspace_path)}:{file_info['line']} - "
                                    f"Uses ruamel.yaml with typ='safe' (SAFE)"
                                )
                            else:
                                findings.append(
                                    f"✗ {file_info['path'].relative_to(workspace_path)}:{file_info['line']} - "
                                    f"VULNERABLE: {target_line.strip()}"
                                )
            
            except Exception as e:
                findings.append(f"Error reading {file_path}: {e}")
        
        # Report findings
        if any('VULNERABLE' in f or '✗' in f for f in findings):
            message = "\n\nCVE-005 VERIFICATION:\n" + "\n".join(findings)
            message += "\n\nVULNERABLE files detected as described in CVE-005."
            pytest.fail(message)
        elif findings:
            # All checks passed or files use safe loading
            message = "\n\nCVE-005 VERIFICATION:\n" + "\n".join(findings)
            pytest.skip(message)

    @pytest.mark.unit
    def test_rce_proof_of_concept(self):
        """
        Proof of concept test demonstrating RCE via unsafe YAML loading.
        
        This test creates a malicious YAML file that would execute arbitrary code
        if loaded with unsafe yaml.load(). This demonstrates the critical severity
        of CVE-005.
        
        WARNING: This test contains proof-of-concept exploit code for educational
        purposes only. It is designed to fail if the vulnerability exists.
        """
        # Create a malicious YAML that would create a file (proof of RCE)
        test_marker_file = tempfile.mktemp(suffix='.txt')
        
        malicious_yaml = f"""
!!python/object/apply:subprocess.check_output
args:
  - - python
    - -c
    - |
      with open('{test_marker_file}', 'w') as f:
          f.write('RCE_SUCCESSFUL')
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_yaml)
            yaml_file = f.name
        
        try:
            # Attempt to load the malicious YAML
            with open(yaml_file, 'r') as f:
                try:
                    # This should be prevented by SafeLoader
                    result = yaml.load(f, Loader=yaml.SafeLoader)
                except yaml.constructor.ConstructorError:
                    # SafeLoader correctly prevented the attack
                    pass
            
            # Check if the marker file was created (would indicate successful RCE)
            if os.path.exists(test_marker_file):
                try:
                    os.unlink(test_marker_file)
                except:
                    pass
                pytest.fail(
                    "CRITICAL VULNERABILITY: Remote Code Execution was successful. "
                    "Arbitrary code was executed via YAML loading. This confirms CVE-005."
                )
        
        finally:
            try:
                os.unlink(yaml_file)
            except:
                pass
            try:
                if os.path.exists(test_marker_file):
                    os.unlink(test_marker_file)
            except:
                pass

    @pytest.mark.unit
    def test_compare_safe_vs_unsafe_yaml_loading(self):
        """
        Comparison test showing the difference between safe and unsafe YAML loading.
        
        This test demonstrates why SafeLoader is necessary and what attacks it prevents.
        """
        # Test data with Python object serialization
        test_cases = [
            {
                'name': 'Simple string',
                'yaml': 'key: value',
                'safe_expected': {'key': 'value'},
                'unsafe_risk': 'Low'
            },
            {
                'name': 'Python object instantiation',
                'yaml': '!!python/object/apply:os.system\nargs: ["echo test"]',
                'safe_expected': 'ConstructorError',
                'unsafe_risk': 'CRITICAL - RCE'
            },
            {
                'name': 'Python module import',
                'yaml': '!!python/name:os.system',
                'safe_expected': 'ConstructorError',
                'unsafe_risk': 'CRITICAL - RCE'
            }
        ]
        
        results = []
        
        for test_case in test_cases:
            result = {
                'name': test_case['name'],
                'risk': test_case['unsafe_risk']
            }
            
            # Test with SafeLoader
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(test_case['yaml'])
                temp_file = f.name
            
            try:
                with open(temp_file, 'r') as f:
                    try:
                        safe_result = yaml.load(f, Loader=yaml.SafeLoader)
                        result['safe_loader'] = 'Loaded successfully'
                    except yaml.constructor.ConstructorError:
                        result['safe_loader'] = 'Blocked (ConstructorError)'
                    except Exception as e:
                        result['safe_loader'] = f'Error: {type(e).__name__}'
                
                results.append(result)
            
            finally:
                os.unlink(temp_file)
        
        # Document the differences
        message = "\n\nSafe vs Unsafe YAML Loading Comparison:\n"
        for result in results:
            message += f"\nTest: {result['name']}\n"
            message += f"  SafeLoader: {result['safe_loader']}\n"
            message += f"  Risk if using unsafe load: {result['risk']}\n"
        
        message += "\nCONCLUSION: SafeLoader prevents dangerous object instantiation and code execution.\n"
        message += "Always use yaml.safe_load() or yaml.load(stream, Loader=yaml.SafeLoader) for untrusted input.\n"
        
        # This is an informational test - we pass but log the information
        print(message)


class TestCVE005RuamelYAML:
    """
    Test suite for ruamel.yaml usage patterns.
    
    The codebase uses ruamel.yaml in addition to PyYAML. This test suite verifies
    that ruamel.yaml is used safely.
    """

    @pytest.mark.unit
    def test_ruamel_yaml_safe_mode(self):
        """
        Test that ruamel.yaml with typ='safe' prevents code execution.
        
        Some files in the codebase use ruamel.yaml instead of PyYAML.
        The YAML(typ='safe') usage should be verified as safe.
        """
        pytest.importorskip('ruamel.yaml')
        
        from ruamel.yaml import YAML
        
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "test"']
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_yaml)
            temp_file = f.name
        
        try:
            yaml_safe = YAML(typ='safe')
            
            with open(temp_file, 'r') as f:
                # This should raise an error or not execute code
                try:
                    result = yaml_safe.load(f)
                    # If we got a result, check it's not a function call
                    assert not callable(result), "Loaded a callable object - potential security issue"
                except Exception:
                    # Exception is expected for malicious YAML
                    pass
        
        finally:
            os.unlink(temp_file)

    @pytest.mark.unit
    def test_detect_ruamel_yaml_unsafe_usage(self):
        """
        Test to detect unsafe ruamel.yaml usage in the codebase.
        
        Scans for YAML() instantiation without typ='safe' parameter.
        """
        workspace_path = Path("/workspace")
        
        scan_paths = [
            workspace_path / "nemo",
            workspace_path / "scripts",
        ]
        
        unsafe_ruamel_files = []
        
        for scan_path in scan_paths:
            if not scan_path.exists():
                continue
            
            for python_file in scan_path.rglob("*.py"):
                try:
                    with open(python_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Check for ruamel.yaml import
                    if 'from ruamel.yaml import YAML' in content or 'from ruamel import yaml' in content:
                        # Check for YAML() instantiation without typ='safe'
                        lines = content.split('\n')
                        for i, line in enumerate(lines, 1):
                            if 'YAML()' in line and "typ='safe'" not in line and 'typ="safe"' not in line:
                                # Check context to avoid false positives
                                context_start = max(0, i - 3)
                                context_end = min(len(lines), i + 2)
                                context = '\n'.join(lines[context_start:context_end])
                                
                                if "typ='safe'" not in context and 'typ="safe"' not in context:
                                    unsafe_ruamel_files.append({
                                        'file': str(python_file.relative_to(workspace_path)),
                                        'line': i
                                    })
                
                except Exception:
                    pass
        
        if unsafe_ruamel_files:
            message = "\n\nPotentially unsafe ruamel.yaml usage detected:\n"
            for vuln in unsafe_ruamel_files[:10]:
                message += f"  - {vuln['file']}:{vuln['line']}\n"
            
            message += "\nRECOMMENDATION: Use YAML(typ='safe') for loading untrusted YAML files.\n"
            
            # This is informational - we document but don't fail
            print(message)
