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

This test suite verifies the vulnerability described in CVE-005, which identifies
potential Remote Code Execution (RCE) vulnerabilities through unsafe YAML loading
in the NeMo codebase.

CVE Details:
- CVE ID: CVE-005
- Title: Remote Code Execution via Unsafe YAML Loading
- Severity: CRITICAL
- Jira Issue: https://ml6team.atlassian.net/browse/DR-137

The vulnerability occurs when yaml.load() is used without specifying a SafeLoader,
allowing arbitrary Python code execution through specially crafted YAML files.

Affected Files:
- nemo/collections/asr/parts/preprocessing/perturb.py:1213
- scripts/nemo_legacy_import/asr_checkpoint_port.py:49
- Other files using yaml.load() without SafeLoader

These tests are designed to:
1. Demonstrate the vulnerability exists when using unsafe yaml.load()
2. Show how malicious YAML payloads can execute arbitrary code
3. Verify that safe alternatives (yaml.safe_load or SafeLoader) prevent exploitation
4. Document the security risk for future developers
"""

import io
import os
import tempfile
from pathlib import Path

import pytest
import yaml


class TestCVE005UnsafeYAMLLoading:
    """
    Test suite for CVE-005: Unsafe YAML Loading Vulnerability
    
    These tests verify that unsafe YAML loading patterns can lead to Remote Code Execution (RCE).
    The tests use a file creation approach to demonstrate the vulnerability in a controlled manner.
    """

    @pytest.mark.unit
    def test_unsafe_yaml_load_vulnerability_file_creation(self):
        """
        Test that demonstrates CVE-005: unsafe yaml.load() allows arbitrary code execution.
        
        This test creates a temporary file as proof-of-concept for RCE. In a real attack,
        malicious YAML could:
        - Execute shell commands
        - Exfiltrate sensitive data
        - Modify system files
        - Install backdoors
        
        EXPECTED BEHAVIOR: This test should PASS if the vulnerability exists,
        meaning the malicious YAML successfully executes code.
        """
        # Create a unique marker file path for this test
        marker_file = tempfile.mktemp(prefix="cve005_test_", suffix=".txt")
        
        # Ensure the marker file doesn't exist before the test
        if os.path.exists(marker_file):
            os.remove(marker_file)
        
        # Malicious YAML payload that creates a file when parsed
        # This demonstrates arbitrary code execution capability
        malicious_yaml = f"""
!!python/object/apply:os.system
args: ['touch {marker_file}']
"""
        
        try:
            # UNSAFE: Using yaml.load() without SafeLoader
            # This is the vulnerable pattern identified in CVE-005
            parsed = yaml.load(malicious_yaml, Loader=yaml.Loader)  # noqa: S506
            
            # If the vulnerability exists, the file should be created
            assert os.path.exists(marker_file), (
                "CVE-005 vulnerability might be partially patched: "
                "yaml.load() did not execute the malicious payload. "
                "However, this could also mean the YAML library version has built-in protections."
            )
            
            # Log success of RCE demonstration
            print(f"\n[SECURITY WARNING] CVE-005 VULNERABILITY CONFIRMED:")
            print(f"  - Arbitrary code executed via yaml.load()")
            print(f"  - Proof: Created marker file at {marker_file}")
            print(f"  - Risk: Malicious YAML can execute ANY Python code")
            
        finally:
            # Cleanup: Remove the marker file
            if os.path.exists(marker_file):
                os.remove(marker_file)

    @pytest.mark.unit
    def test_unsafe_yaml_load_with_default_loader(self):
        """
        Test yaml.load() with default Loader (FullLoader in PyYAML >= 5.1)
        
        Note: PyYAML >= 5.1 changed the default loader to FullLoader, which blocks
        arbitrary code execution. However, explicit use of yaml.Loader or yaml.UnsafeLoader
        still poses a risk.
        """
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "malicious"']
"""
        
        # Test with default loader (should be safer in newer PyYAML versions)
        # But this still raises awareness about the API
        try:
            # Using yaml.load() without specifying Loader is deprecated and risky
            with pytest.warns(yaml.YAMLLoadWarning):
                # In PyYAML >= 5.1, this should raise a warning
                parsed = yaml.load(malicious_yaml)  # noqa: S506
        except yaml.constructor.ConstructorError:
            # If we get a ConstructorError, it means the default loader blocked execution
            print("\n[INFO] Default loader blocked malicious YAML (PyYAML >= 5.1 behavior)")

    @pytest.mark.unit
    def test_unsafe_yaml_unsafe_loader_vulnerability(self):
        """
        Test that yaml.load() with UnsafeLoader allows code execution.
        
        This is the most dangerous pattern and should NEVER be used with untrusted input.
        """
        marker_file = tempfile.mktemp(prefix="cve005_unsafe_loader_", suffix=".txt")
        
        if os.path.exists(marker_file):
            os.remove(marker_file)
        
        malicious_yaml = f"""
!!python/object/apply:os.system
args: ['touch {marker_file}']
"""
        
        try:
            # CRITICAL VULNERABILITY: Using UnsafeLoader
            parsed = yaml.load(malicious_yaml, Loader=yaml.UnsafeLoader)  # noqa: S506
            
            assert os.path.exists(marker_file), (
                "Expected UnsafeLoader to execute malicious code"
            )
            
            print(f"\n[CRITICAL] yaml.UnsafeLoader ALLOWS CODE EXECUTION:")
            print(f"  - Created file: {marker_file}")
            print(f"  - Never use UnsafeLoader with untrusted input!")
            
        finally:
            if os.path.exists(marker_file):
                os.remove(marker_file)

    @pytest.mark.unit
    def test_safe_yaml_safe_load_blocks_execution(self):
        """
        Test that yaml.safe_load() properly blocks malicious code execution.
        
        This is the RECOMMENDED way to load YAML from untrusted sources.
        
        EXPECTED BEHAVIOR: This test should PASS when safe_load() successfully
        blocks the malicious payload.
        """
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "This should not execute"']
"""
        
        # SAFE: Using yaml.safe_load()
        with pytest.raises(yaml.constructor.ConstructorError) as exc_info:
            yaml.safe_load(malicious_yaml)
        
        # Verify that the error is due to blocked code execution
        assert "could not determine a constructor" in str(exc_info.value).lower() or \
               "!!python/object/apply" in str(exc_info.value), (
            "safe_load() should block !!python/object/apply tags"
        )
        
        print("\n[SECURE] yaml.safe_load() successfully blocked malicious payload")

    @pytest.mark.unit
    def test_safe_yaml_safeloader_blocks_execution(self):
        """
        Test that yaml.load() with SafeLoader properly blocks malicious code execution.
        
        This is an alternative safe approach: yaml.load(stream, Loader=yaml.SafeLoader)
        
        EXPECTED BEHAVIOR: This test should PASS when SafeLoader successfully
        blocks the malicious payload.
        """
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "This should not execute"']
"""
        
        # SAFE: Using yaml.load() with explicit SafeLoader
        with pytest.raises(yaml.constructor.ConstructorError) as exc_info:
            yaml.load(malicious_yaml, Loader=yaml.SafeLoader)
        
        # Verify that the error is due to blocked code execution
        assert "could not determine a constructor" in str(exc_info.value).lower() or \
               "!!python/object/apply" in str(exc_info.value), (
            "SafeLoader should block !!python/object/apply tags"
        )
        
        print("\n[SECURE] yaml.SafeLoader successfully blocked malicious payload")

    @pytest.mark.unit
    def test_malicious_yaml_object_instantiation(self):
        """
        Test another attack vector: malicious object instantiation.
        
        Unsafe YAML loading can instantiate arbitrary Python objects, potentially
        calling __init__ methods with attacker-controlled parameters.
        """
        # This YAML attempts to instantiate a Path object and call methods
        malicious_yaml = """
!!python/object/new:pathlib.Path
args: ['/etc/passwd']
"""
        
        # UNSAFE: Load with Loader
        obj = yaml.load(malicious_yaml, Loader=yaml.Loader)  # noqa: S506
        
        # Verify object was instantiated (demonstrating the vulnerability)
        assert isinstance(obj, Path), "Unsafe loader should allow object instantiation"
        assert str(obj) == '/etc/passwd', "Object should be instantiated with attacker's parameters"
        
        print("\n[SECURITY WARNING] Unsafe YAML loading allows arbitrary object instantiation:")
        print(f"  - Instantiated object: {obj}")
        print(f"  - Type: {type(obj)}")
        
        # SAFE: Verify safe_load blocks this
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.safe_load(malicious_yaml)
        
        print("  - yaml.safe_load() correctly blocked this attack")

    @pytest.mark.unit
    def test_yaml_load_with_baseloader(self):
        """
        Test yaml.BaseLoader as a middle ground.
        
        BaseLoader is more restrictive than FullLoader but less restrictive than SafeLoader.
        For security-critical applications, SafeLoader should be preferred.
        """
        # Simple YAML that should work with BaseLoader
        simple_yaml = """
key: value
number: 123
"""
        
        result = yaml.load(simple_yaml, Loader=yaml.BaseLoader)
        assert result == {'key': 'value', 'number': '123'}  # Note: BaseLoader keeps everything as strings
        
        # Malicious YAML should be blocked
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "test"']
"""
        
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.load(malicious_yaml, Loader=yaml.BaseLoader)
        
        print("\n[INFO] yaml.BaseLoader blocks Python-specific tags")

    @pytest.mark.unit
    def test_identify_vulnerable_patterns_in_codebase(self):
        """
        Test to identify and document vulnerable patterns found in the NeMo codebase.
        
        This test documents the specific vulnerable instances identified in CVE-005.
        """
        # These are the known vulnerable patterns identified in the CVE
        vulnerable_files = [
            "nemo/collections/asr/parts/preprocessing/perturb.py:1213",
            "scripts/nemo_legacy_import/asr_checkpoint_port.py:49",
        ]
        
        print("\n[CVE-005] Vulnerable file locations identified:")
        for location in vulnerable_files:
            print(f"  - {location}")
        
        print("\nVulnerable pattern: yaml.load(f) without SafeLoader")
        print("Recommended fix: yaml.safe_load(f) or yaml.load(f, Loader=yaml.SafeLoader)")
        
        # This test serves as documentation
        assert len(vulnerable_files) > 0, "CVE-005 identified vulnerable locations"


class TestCVE005RealWorldScenarios:
    """
    Test suite demonstrating real-world attack scenarios for CVE-005.
    """

    @pytest.mark.unit
    def test_malicious_config_file_attack(self):
        """
        Test scenario: Attacker provides a malicious configuration file.
        
        In ML frameworks like NeMo, configuration files are commonly loaded from:
        - User uploads
        - Remote repositories
        - Shared storage
        
        This test simulates an attack where a malicious config file is loaded.
        """
        # Create a temporary malicious config file
        malicious_config = tempfile.mktemp(suffix=".yaml")
        marker_file = tempfile.mktemp(prefix="cve005_config_attack_", suffix=".txt")
        
        try:
            # Write malicious YAML to a file
            with open(malicious_config, 'w') as f:
                f.write(f"""
# This looks like a normal config file
model:
  name: "test_model"
  version: "1.0"

# But contains malicious code hidden in the YAML
_malicious: !!python/object/apply:os.system
  args: ['touch {marker_file}']
""")
            
            # Simulate loading the config file (UNSAFE)
            with open(malicious_config, 'r') as f:
                config = yaml.load(f, Loader=yaml.Loader)  # noqa: S506
            
            # Verify the attack succeeded
            assert os.path.exists(marker_file), (
                "Malicious config file should execute code when loaded unsafely"
            )
            
            print("\n[ATTACK SCENARIO] Malicious config file attack successful:")
            print(f"  - Loaded config from: {malicious_config}")
            print(f"  - Executed code, created: {marker_file}")
            print(f"  - Attacker could have: stolen data, installed backdoor, etc.")
            
        finally:
            # Cleanup
            if os.path.exists(malicious_config):
                os.remove(malicious_config)
            if os.path.exists(marker_file):
                os.remove(marker_file)

    @pytest.mark.unit
    def test_safe_config_loading_prevents_attack(self):
        """
        Test that safe loading patterns prevent the config file attack.
        
        This demonstrates the correct way to load configuration files.
        """
        malicious_config = tempfile.mktemp(suffix=".yaml")
        
        try:
            # Write malicious YAML to a file
            with open(malicious_config, 'w') as f:
                f.write("""
model:
  name: "test_model"
  
_malicious: !!python/object/apply:os.system
  args: ['echo "attack"']
""")
            
            # SAFE: Load with safe_load
            with open(malicious_config, 'r') as f:
                with pytest.raises(yaml.constructor.ConstructorError):
                    config = yaml.safe_load(f)
            
            print("\n[DEFENSE] Safe loading prevented malicious config attack:")
            print(f"  - yaml.safe_load() blocked code execution")
            print(f"  - Application remained secure")
            
        finally:
            if os.path.exists(malicious_config):
                os.remove(malicious_config)

    @pytest.mark.unit
    def test_environment_variable_exfiltration_attack(self):
        """
        Test scenario: Attacker attempts to exfiltrate environment variables.
        
        This demonstrates how unsafe YAML loading could be used to steal sensitive
        information like API keys, credentials, etc.
        """
        # Set a dummy environment variable to exfiltrate
        os.environ['CVE005_TEST_SECRET'] = 'super_secret_key_12345'
        
        exfil_file = tempfile.mktemp(prefix="cve005_exfil_", suffix=".txt")
        
        try:
            # Malicious YAML that attempts to exfiltrate env vars
            # Note: This is a simplified example; real attacks could be more sophisticated
            malicious_yaml = f"""
!!python/object/apply:os.system
args: ['printenv CVE005_TEST_SECRET > {exfil_file}']
"""
            
            # UNSAFE: Load the malicious YAML
            yaml.load(malicious_yaml, Loader=yaml.Loader)  # noqa: S506
            
            # In a real attack, the file would contain the secret
            # (may not work on all systems due to shell specifics, but demonstrates the concept)
            print("\n[ATTACK SCENARIO] Environment variable exfiltration attempt:")
            print(f"  - Attempted to steal: CVE005_TEST_SECRET")
            print(f"  - Output file: {exfil_file}")
            print(f"  - Real attackers could exfiltrate: AWS keys, tokens, passwords, etc.")
            
        finally:
            # Cleanup
            if os.path.exists(exfil_file):
                os.remove(exfil_file)
            del os.environ['CVE005_TEST_SECRET']

    @pytest.mark.unit
    def test_nested_malicious_yaml_in_valid_config(self):
        """
        Test that malicious code can be hidden in otherwise valid-looking configs.
        
        This test shows how attackers can hide malicious payloads in legitimate-looking
        configuration structures.
        """
        marker_file = tempfile.mktemp(prefix="cve005_nested_", suffix=".txt")
        
        try:
            # Complex config with hidden malicious code
            malicious_yaml = f"""
# Legitimate-looking training configuration
training:
  batch_size: 32
  epochs: 100
  learning_rate: 0.001
  
model:
  architecture: "transformer"
  layers: 12
  hidden_size: 768
  
# Hidden malicious code in preprocessing section
preprocessing:
  augmentation: !!python/object/apply:os.system
    args: ['touch {marker_file}']
  normalization: "standard"
"""
            
            # UNSAFE: Load config
            config = yaml.load(malicious_yaml, Loader=yaml.Loader)  # noqa: S506
            
            # Verify attack succeeded
            assert os.path.exists(marker_file), (
                "Malicious code hidden in valid config should execute"
            )
            
            print("\n[ATTACK SCENARIO] Hidden malicious code in valid-looking config:")
            print(f"  - Config appears legitimate with training/model parameters")
            print(f"  - Malicious code hidden in 'preprocessing.augmentation'")
            print(f"  - Code executed, created: {marker_file}")
            
        finally:
            if os.path.exists(marker_file):
                os.remove(marker_file)


class TestCVE005Mitigations:
    """
    Test suite for CVE-005 mitigation strategies.
    """

    @pytest.mark.unit
    def test_recommended_safe_yaml_loading_patterns(self):
        """
        Document and test recommended safe YAML loading patterns.
        """
        safe_yaml = """
model:
  name: "test_model"
  layers: 12
training:
  batch_size: 32
"""
        
        print("\n[MITIGATION] Recommended safe YAML loading patterns:")
        
        # Pattern 1: yaml.safe_load()
        config1 = yaml.safe_load(safe_yaml)
        assert config1['model']['name'] == 'test_model'
        print("  ✓ Pattern 1: yaml.safe_load(stream)")
        
        # Pattern 2: yaml.load() with SafeLoader
        config2 = yaml.load(safe_yaml, Loader=yaml.SafeLoader)
        assert config2['model']['name'] == 'test_model'
        print("  ✓ Pattern 2: yaml.load(stream, Loader=yaml.SafeLoader)")
        
        # Pattern 3: Using ruamel.yaml with safe type
        try:
            from ruamel.yaml import YAML
            yaml_safe = YAML(typ='safe')
            config3 = yaml_safe.load(safe_yaml)
            assert config3['model']['name'] == 'test_model'
            print("  ✓ Pattern 3: YAML(typ='safe').load(stream)")
        except ImportError:
            print("  ⚠ Pattern 3: ruamel.yaml not available (optional)")
        
        print("\n  All patterns successfully loaded safe YAML")
        print("  All patterns block malicious YAML payloads")

    @pytest.mark.unit
    def test_unsafe_patterns_to_avoid(self):
        """
        Document unsafe patterns that should be avoided.
        """
        print("\n[MITIGATION] Unsafe patterns to AVOID:")
        print("  ✗ yaml.load(stream)  # Deprecated, no loader specified")
        print("  ✗ yaml.load(stream, Loader=yaml.Loader)  # Allows code execution")
        print("  ✗ yaml.load(stream, Loader=yaml.UnsafeLoader)  # Explicitly unsafe")
        print("  ✗ yaml.unsafe_load(stream)  # Obviously dangerous")
        
        print("\n  These patterns allow arbitrary code execution!")
        print("  Replace ALL occurrences with safe alternatives")

    @pytest.mark.unit
    def test_input_validation_as_defense_in_depth(self):
        """
        Test input validation as an additional security layer.
        
        While safe YAML loading is the primary defense, validating YAML structure
        provides defense-in-depth.
        """
        # Example of input validation
        safe_yaml = """
model:
  name: "test"
"""
        
        config = yaml.safe_load(safe_yaml)
        
        # Validate expected structure
        assert 'model' in config, "Config must have 'model' key"
        assert isinstance(config['model'], dict), "'model' must be a dictionary"
        
        print("\n[DEFENSE IN DEPTH] Input validation recommendations:")
        print("  1. Use yaml.safe_load() as primary defense")
        print("  2. Validate YAML structure matches expected schema")
        print("  3. Sanitize/validate all string values")
        print("  4. Use type checking for config values")
        print("  5. Implement allowlists for acceptable values")
        print("  6. Log and monitor config file loads")
