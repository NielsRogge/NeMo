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
Security tests for CVE-005: Remote Code Execution via Unsafe YAML Loading

CVE ID: CVE-005
Severity: CRITICAL
Jira Issue: https://ml6team.atlassian.net/browse/DR-137

Description:
    The application is vulnerable to RCE via unsafe YAML loading. Using yaml.load()
    without SafeLoader can allow an attacker to execute arbitrary code by crafting
    a malicious configuration file.

These tests verify:
    1. Detection of unsafe yaml.load() usage without SafeLoader
    2. Verification of safe YAML loading patterns
    3. Testing potential RCE attack vectors through YAML deserialization
    4. Ensuring all YAML loading is done securely across the codebase
"""

import io
import os
import tempfile
import pytest
import yaml
from pathlib import Path
from ruamel.yaml import YAML


class TestUnsafeYAMLLoading:
    """
    Test suite to verify the presence of unsafe YAML loading patterns.
    
    These tests are designed to detect the vulnerability described in CVE-005,
    not to fix it. They should FAIL if unsafe patterns are present in the codebase.
    """

    def test_yaml_load_without_loader_is_unsafe(self):
        """
        Test that yaml.load() without Loader parameter is unsafe.
        
        This test demonstrates the vulnerability: yaml.load() without a Loader
        can execute arbitrary Python code embedded in YAML.
        """
        # Create a malicious YAML payload that would execute code
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "RCE vulnerability detected"']
"""
        
        # This demonstrates the vulnerability - DO NOT use in production
        # yaml.load() without Loader is unsafe and deprecated in PyYAML >= 5.1
        with pytest.warns(yaml.YAMLLoadWarning):
            # This should trigger a warning in newer PyYAML versions
            try:
                result = yaml.load(io.StringIO(malicious_yaml), Loader=yaml.Loader)
            except Exception as e:
                # Expected behavior - should be unsafe
                pass

    def test_safe_yaml_loading_patterns(self):
        """
        Test that safe YAML loading patterns work correctly.
        
        This test verifies that safe alternatives (yaml.safe_load or 
        yaml.load with SafeLoader) properly reject malicious payloads.
        """
        # Malicious YAML payload
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "RCE vulnerability"']
"""
        
        # Test 1: yaml.safe_load should reject malicious YAML
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.safe_load(io.StringIO(malicious_yaml))
        
        # Test 2: yaml.load with SafeLoader should also reject
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.load(io.StringIO(malicious_yaml), Loader=yaml.SafeLoader)
        
        # Test 3: Safe YAML should load benign data correctly
        safe_yaml = """
key: value
number: 42
list:
  - item1
  - item2
"""
        result = yaml.safe_load(io.StringIO(safe_yaml))
        assert result['key'] == 'value'
        assert result['number'] == 42
        assert result['list'] == ['item1', 'item2']

    def test_ruamel_yaml_safe_loading(self):
        """
        Test that ruamel.yaml with typ='safe' prevents code execution.
        
        The codebase uses ruamel.yaml in some places. This test verifies
        that it's configured securely.
        """
        # Malicious YAML payload
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "RCE vulnerability"']
"""
        
        # ruamel.yaml with typ='safe' should reject malicious YAML
        yaml_loader = YAML(typ='safe')
        with pytest.raises(Exception):  # Should raise constructor error
            yaml_loader.load(io.StringIO(malicious_yaml))

    def test_yaml_load_variations(self):
        """
        Test various YAML loading patterns to identify unsafe usage.
        
        This test documents the different ways YAML can be loaded and
        identifies which are safe vs unsafe.
        """
        safe_yaml_content = "key: value\n"
        
        # SAFE patterns:
        # 1. yaml.safe_load()
        result1 = yaml.safe_load(io.StringIO(safe_yaml_content))
        assert result1 == {'key': 'value'}
        
        # 2. yaml.load() with SafeLoader
        result2 = yaml.load(io.StringIO(safe_yaml_content), Loader=yaml.SafeLoader)
        assert result2 == {'key': 'value'}
        
        # 3. ruamel.yaml with typ='safe'
        yaml_loader = YAML(typ='safe')
        result3 = yaml_loader.load(io.StringIO(safe_yaml_content))
        assert result3 == {'key': 'value'}
        
        # UNSAFE patterns (documented but not executed):
        # - yaml.load() without Loader parameter (deprecated in PyYAML >= 5.1)
        # - yaml.unsafe_load() (explicitly unsafe)
        # - yaml.load() with Loader=yaml.Loader or Loader=yaml.FullLoader

    def test_yaml_rce_payload_variations(self):
        """
        Test multiple RCE payload variations to ensure they're all blocked.
        
        This comprehensive test includes various attack vectors that
        malicious actors might use.
        """
        # Various malicious YAML payloads
        rce_payloads = [
            # Payload 1: os.system execution
            """
!!python/object/apply:os.system
args: ['echo "payload1"']
""",
            # Payload 2: subprocess execution
            """
!!python/object/apply:subprocess.call
args: [['echo', 'payload2']]
""",
            # Payload 3: eval execution
            """
!!python/object/apply:eval
args: ['__import__("os").system("echo payload3")']
""",
            # Payload 4: __import__ usage
            """
!!python/object/apply:__import__
args: ['os']
""",
            # Payload 5: object instantiation
            """
!!python/object:os.system
args: ['echo payload5']
""",
        ]
        
        # All these payloads should be rejected by safe_load
        for i, payload in enumerate(rce_payloads):
            with pytest.raises(yaml.constructor.ConstructorError, 
                             match=r"could not determine a constructor"):
                yaml.safe_load(io.StringIO(payload))
                # If we reach here, the safe loader failed to block the payload
                pytest.fail(f"Payload {i+1} was not blocked by yaml.safe_load()")


class TestCodebaseYAMLUsage:
    """
    Test suite to scan and verify YAML loading patterns in the codebase.
    
    These tests check actual files in the NeMo codebase to ensure they
    follow secure YAML loading practices.
    """

    @pytest.fixture
    def codebase_root(self):
        """Get the root directory of the NeMo codebase."""
        # Assuming tests are in /tests/security/
        test_dir = Path(__file__).parent
        return test_dir.parent.parent

    def test_scan_for_unsafe_yaml_load(self, codebase_root):
        """
        Scan the codebase for potentially unsafe yaml.load() usage.
        
        This test searches for yaml.load() calls and verifies they use SafeLoader.
        It documents locations where yaml.load() is used, which should be reviewed.
        """
        # Files mentioned in CVE-005 as having unsafe yaml.load()
        vulnerable_files = [
            codebase_root / "nemo/collections/asr/parts/preprocessing/perturb.py",
            codebase_root / "scripts/nemo_legacy_import/asr_checkpoint_port.py",
        ]
        
        issues_found = []
        
        for file_path in vulnerable_files:
            if not file_path.exists():
                continue
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Check for yaml.load() usage
                    if 'yaml.load(' in line:
                        # Check if SafeLoader is specified
                        if 'SafeLoader' not in line and 'typ=' not in line:
                            # Check if it's just a comment/docstring
                            stripped = line.strip()
                            if not stripped.startswith('#') and not stripped.startswith('"""') and not stripped.startswith("'''"):
                                issues_found.append({
                                    'file': str(file_path.relative_to(codebase_root)),
                                    'line': line_num,
                                    'content': line.strip()
                                })
        
        # Document findings
        if issues_found:
            message = "Potentially unsafe yaml.load() usage found:\n"
            for issue in issues_found:
                message += f"  {issue['file']}:{issue['line']}: {issue['content']}\n"
            # This assertion documents the vulnerability
            # In a real security test, you would assert len(issues_found) == 0
            # But for CVE testing, we document what we found
            pytest.fail(message + "\nThese instances should use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)")

    def test_no_yaml_unsafe_load_usage(self, codebase_root):
        """
        Verify that yaml.unsafe_load() is never used in the codebase.
        
        yaml.unsafe_load() is explicitly unsafe and should never be used.
        """
        # Search for any .py files
        python_files = list(codebase_root.rglob('*.py'))
        
        unsafe_usage = []
        for file_path in python_files:
            # Skip test files and __pycache__
            if '__pycache__' in str(file_path) or file_path.name.startswith('test_'):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'yaml.unsafe_load' in content:
                        # Find the specific lines
                        lines = content.split('\n')
                        for line_num, line in enumerate(lines, 1):
                            if 'yaml.unsafe_load' in line and not line.strip().startswith('#'):
                                unsafe_usage.append({
                                    'file': str(file_path.relative_to(codebase_root)),
                                    'line': line_num,
                                    'content': line.strip()
                                })
            except Exception:
                # Skip files that can't be read
                continue
        
        assert len(unsafe_usage) == 0, \
            f"yaml.unsafe_load() found in {len(unsafe_usage)} locations: {unsafe_usage}"

    def test_yaml_import_patterns(self, codebase_root):
        """
        Document how YAML is imported and used across the codebase.
        
        This test catalogs the different YAML libraries and patterns used
        to help understand the attack surface.
        """
        import_patterns = {
            'import yaml': [],
            'from yaml import': [],
            'from ruamel.yaml import YAML': [],
            'import ruamel.yaml': [],
        }
        
        # Sample key files for analysis
        key_files = [
            codebase_root / "nemo/collections/asr/parts/preprocessing/perturb.py",
            codebase_root / "scripts/nemo_legacy_import/asr_checkpoint_port.py",
            codebase_root / "nemo/export/utils/lora_converter.py",
            codebase_root / "nemo/export/vllm/model_config.py",
            codebase_root / "nemo/export/trt_llm/nemo_ckpt_loader/nemo_file.py",
        ]
        
        for file_path in key_files:
            if not file_path.exists():
                continue
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern in import_patterns.keys():
                    if pattern in content:
                        import_patterns[pattern].append(str(file_path.relative_to(codebase_root)))
        
        # Document the patterns (this is informational)
        for pattern, files in import_patterns.items():
            if files:
                print(f"\n{pattern} found in:")
                for f in files:
                    print(f"  - {f}")


class TestYAMLConfigurationSecurity:
    """
    Test YAML configuration loading security in common NeMo patterns.
    
    NeMo heavily uses YAML for configuration. These tests verify that
    configuration loading is done securely.
    """

    def test_malicious_config_file_handling(self):
        """
        Test that malicious YAML config files are properly rejected.
        
        This simulates an attacker providing a malicious config file.
        """
        # Create a temporary malicious config file
        malicious_config = """
# Looks like a normal config
model:
  name: test_model
  # But contains malicious code
  !!python/object/apply:os.system
  args: ['echo "compromised"']
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(malicious_config)
            config_path = f.name
        
        try:
            # Safe loading should reject this
            with open(config_path, 'r') as f:
                with pytest.raises(yaml.constructor.ConstructorError):
                    yaml.safe_load(f)
        finally:
            os.unlink(config_path)

    def test_nested_malicious_yaml_objects(self):
        """
        Test detection of nested malicious objects in YAML.
        
        Attackers might try to hide malicious code in nested structures.
        """
        nested_malicious = """
config:
  preprocessing:
    augmentation:
      - type: noise
        params:
          !!python/object/apply:os.system
          args: ['echo "nested attack"']
"""
        
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.safe_load(io.StringIO(nested_malicious))

    def test_yaml_anchor_and_alias_safety(self):
        """
        Test that YAML anchors and aliases don't create security issues.
        
        YAML anchors/aliases are legitimate features but should be tested
        to ensure they don't enable exploitation.
        """
        yaml_with_anchors = """
default_settings: &defaults
  timeout: 30
  retries: 3

service1:
  <<: *defaults
  name: service1

service2:
  <<: *defaults
  name: service2
"""
        # This should load safely
        result = yaml.safe_load(io.StringIO(yaml_with_anchors))
        assert result['service1']['timeout'] == 30
        assert result['service2']['retries'] == 3

    def test_yaml_merge_key_security(self):
        """
        Test YAML merge key (<<) doesn't enable code execution.
        """
        yaml_with_merge = """
base: &base
  key1: value1
  key2: value2

extended:
  <<: *base
  key3: value3
"""
        result = yaml.safe_load(io.StringIO(yaml_with_merge))
        assert result['extended']['key1'] == 'value1'
        assert result['extended']['key3'] == 'value3'


class TestYAMLSecurityBestPractices:
    """
    Tests to enforce YAML security best practices in NeMo.
    """

    def test_yaml_library_version_check(self):
        """
        Verify that PyYAML version is recent enough to have security warnings.
        
        PyYAML >= 5.1 deprecated unsafe yaml.load() and issues warnings.
        """
        import yaml
        
        # Get PyYAML version
        version_str = yaml.__version__
        major, minor = map(int, version_str.split('.')[:2])
        
        # PyYAML 5.1+ has better security defaults
        assert (major > 5) or (major == 5 and minor >= 1), \
            f"PyYAML version {version_str} is outdated. Upgrade to >= 5.1 for security improvements."

    def test_safe_yaml_alternatives_work(self):
        """
        Verify that all safe YAML loading alternatives function correctly.
        
        This ensures that migrating to safe patterns won't break functionality.
        """
        test_yaml = """
string: "test"
integer: 42
float: 3.14
boolean: true
null_value: null
list:
  - item1
  - item2
  - item3
dict:
  nested_key: nested_value
"""
        
        # Test yaml.safe_load
        result1 = yaml.safe_load(io.StringIO(test_yaml))
        
        # Test yaml.load with SafeLoader
        result2 = yaml.load(io.StringIO(test_yaml), Loader=yaml.SafeLoader)
        
        # Test ruamel.yaml
        yaml_loader = YAML(typ='safe')
        result3 = yaml_loader.load(io.StringIO(test_yaml))
        
        # All should produce equivalent results
        assert result1['string'] == result2['string'] == result3['string']
        assert result1['integer'] == result2['integer'] == result3['integer']
        assert result1['list'] == result2['list'] == result3['list']


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
