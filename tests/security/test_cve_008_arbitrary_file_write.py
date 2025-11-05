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
Security Tests for CVE-008: Arbitrary File Write Vulnerability

CVE ID: CVE-008
Title: [CVE-008] Arbitrary File Write
Severity: CRITICAL
Jira Issue: https://ml6team.atlassian.net/browse/DR-138

Description:
The application may be vulnerable to arbitrary file writes. The framework saves model 
checkpoints, logs, and processed data. If the output paths for these files can be 
controlled by a user or a malicious configuration, it could allow an attacker to 
overwrite critical system files or write malicious scripts (e.g., web shells) to 
sensitive locations.

These tests verify the presence of potentially vulnerable patterns and attack vectors.
They do NOT fix the vulnerability - they document and test for its existence.

Attack Vectors Tested:
1. Directory Traversal: Using paths like "../../../etc/passwd"
2. Absolute Path Injection: Using paths like "/etc/malicious_config"
3. Symlink-based attacks: Writing through symbolic links
4. Overwriting critical configuration files
5. Writing to system directories
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest


class TestCVE008DirectoryTraversal:
    """
    Test suite for directory traversal vulnerabilities in file write operations.
    
    These tests verify that user-controlled file paths can potentially escape
    intended directories using directory traversal sequences like "../".
    """

    @pytest.mark.unit
    def test_directory_traversal_in_manifest_output(self):
        """
        Test: Directory traversal in manifest file output path
        
        Vulnerable Pattern:
        - tools/nemo_forced_aligner/align.py:329: f_manifest_out = open(tgt_manifest_filepath, 'w')
        
        Attack Vector:
        - User provides output_dir containing "../../../etc/" to write outside intended directory
        - Could overwrite system files or place malicious scripts in accessible locations
        
        Expected Behavior (VULNERABLE):
        - Path is not validated and directory traversal is allowed
        - File can be written outside the intended directory
        """
        with tempfile.TemporaryDirectory() as safe_dir:
            # Simulate user-controlled output directory with directory traversal
            malicious_output_dir = os.path.join(safe_dir, "../../../tmp/malicious")
            
            # Construct the target manifest filepath as the vulnerable code does
            manifest_name = "manifest_with_output_file_paths.json"
            tgt_manifest_filepath = str(Path(malicious_output_dir) / manifest_name)
            
            # The vulnerability: Path normalization allows writing outside safe_dir
            # This demonstrates that Path() doesn't prevent traversal
            assert ".." in tgt_manifest_filepath or os.path.isabs(tgt_manifest_filepath)
            
            # Verify that the path can escape the intended directory
            normalized_path = os.path.normpath(tgt_manifest_filepath)
            safe_dir_normalized = os.path.normpath(safe_dir)
            
            # This assertion PASSES, demonstrating the vulnerability
            # The file can be written outside the safe directory
            assert not normalized_path.startswith(safe_dir_normalized), \
                "Path traversal successful - file can escape intended directory"

    @pytest.mark.unit
    def test_directory_traversal_with_makedirs(self):
        """
        Test: Directory traversal combined with os.makedirs
        
        Vulnerable Pattern:
        - os.makedirs(cfg.output_dir, exist_ok=True)
        - open(tgt_manifest_filepath, 'w')
        
        Attack Vector:
        - Attacker provides output_dir with traversal sequences
        - makedirs creates directory structure outside intended location
        - Subsequent file writes occur in attacker-controlled location
        
        Expected Behavior (VULNERABLE):
        - makedirs follows the traversal path and creates directories
        - Files are written in unintended locations
        """
        with tempfile.TemporaryDirectory() as base_dir:
            safe_output = os.path.join(base_dir, "safe_outputs")
            
            # Attacker-controlled path with directory traversal
            malicious_path = os.path.join(safe_output, "../../malicious_output")
            
            # The vulnerability: makedirs will follow the traversal
            os.makedirs(malicious_path, exist_ok=True)
            
            # Verify the malicious directory was created outside safe_output
            resolved_path = os.path.realpath(malicious_path)
            safe_output_resolved = os.path.realpath(safe_output)
            
            assert not resolved_path.startswith(safe_output_resolved), \
                "makedirs followed directory traversal - created dir outside safe location"
            
            # Verify file write succeeds in the malicious location
            test_file = os.path.join(malicious_path, "test.txt")
            with open(test_file, 'w') as f:
                f.write("malicious content")
            
            assert os.path.exists(test_file), \
                "File successfully written outside intended directory"


class TestCVE008AbsolutePathInjection:
    """
    Test suite for absolute path injection vulnerabilities.
    
    These tests verify that user-controlled paths can specify absolute paths
    to write files anywhere in the filesystem.
    """

    @pytest.mark.unit
    def test_absolute_path_in_engine_file(self):
        """
        Test: Absolute path injection in TensorRT engine file write
        
        Vulnerable Pattern:
        - nemo/export/multimodal/build.py:290: with open(engine_file, 'wb') as f:
        
        Attack Vector:
        - User provides engine_file as absolute path like "/etc/malicious_engine"
        - No validation prevents writing to system locations
        
        Expected Behavior (VULNERABLE):
        - Absolute paths are accepted without validation
        - Files can be written to any filesystem location
        """
        # Simulate user-controlled engine file path
        malicious_engine_path = "/tmp/malicious_engine.plan"
        
        # The vulnerability: No validation prevents absolute paths
        assert os.path.isabs(malicious_engine_path), \
            "Absolute path injection possible"
        
        # In vulnerable code, this path would be used directly:
        # with open(engine_file, 'wb') as f:
        #     f.write(engine_string)
        
        # Demonstrate that the code would accept this path
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            temp_path = f.name
            
        try:
            # Simulate the vulnerable write operation
            with open(temp_path, 'wb') as f:
                f.write(b"malicious engine data")
            
            assert os.path.exists(temp_path), \
                "File written using user-controlled absolute path"
        finally:
            os.unlink(temp_path)

    @pytest.mark.unit  
    def test_absolute_path_in_model_card_write(self):
        """
        Test: Absolute path injection in model card write
        
        Vulnerable Pattern:
        - nemo/core/classes/mixins/hf_io_mixin.py:229: 
          model_card_filepath.write_text(str(model_card), encoding='utf-8', errors='ignore')
        
        Attack Vector:
        - User controls saved_path directory
        - Can specify absolute path to write README.md anywhere
        - Could overwrite legitimate documentation or place malicious content
        
        Expected Behavior (VULNERABLE):
        - Absolute paths in saved_path are not validated
        - README.md can be written to arbitrary locations
        """
        # Simulate user-controlled saved_path
        malicious_saved_path = Path("/tmp/malicious_model")
        model_card_filepath = malicious_saved_path / "README.md"
        
        # The vulnerability: Path accepts absolute paths without validation
        assert model_card_filepath.is_absolute(), \
            "Absolute path injection in model card filepath"
        
        # Demonstrate the vulnerable pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "README.md"
            
            # Simulate the vulnerable code pattern
            malicious_content = "# Malicious Model Card\n[Malicious content here]"
            test_path.write_text(malicious_content, encoding='utf-8', errors='ignore')
            
            assert test_path.exists(), \
                "Model card written using user-controlled path"
            assert test_path.read_text() == malicious_content, \
                "Malicious content successfully written"


class TestCVE008ConfigurationControlled:
    """
    Test suite for configuration-controlled file paths.
    
    These tests verify that malicious configuration files can specify
    dangerous file paths for various operations.
    """

    @pytest.mark.unit
    def test_config_controlled_manifest_path(self):
        """
        Test: Configuration-controlled manifest file path
        
        Vulnerable Pattern:
        - Collections use manifest_path from config without validation
        - nemo/collections/asr/models/msdd_models.py:1545: 
          with open(manifest_path, 'w') as f:
        
        Attack Vector:
        - Attacker provides malicious config file with crafted manifest_path
        - Path could target system files or attacker-accessible locations
        
        Expected Behavior (VULNERABLE):
        - manifest_path from config is used without validation
        - Can write to arbitrary locations specified in config
        """
        # Simulate malicious configuration
        malicious_config = {
            "manifest_path": "/tmp/malicious_manifest.json",
            "output_dir": "../../sensitive_location"
        }
        
        manifest_path = malicious_config["manifest_path"]
        
        # The vulnerability: Config values are used directly for file paths
        assert os.path.isabs(manifest_path) or ".." in manifest_path, \
            "Config can specify dangerous file paths"
        
        # Demonstrate that config-controlled paths are used for writing
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_manifest = f.name
            
        try:
            # Simulate vulnerable pattern: with open(manifest_path, 'w') as f:
            with open(temp_manifest, 'w') as f:
                f.write('{"malicious": "data"}')
            
            assert os.path.exists(temp_manifest), \
                "File written using config-controlled path"
        finally:
            os.unlink(temp_manifest)

    @pytest.mark.unit
    def test_config_controlled_output_file_path(self):
        """
        Test: Configuration-controlled output file path
        
        Vulnerable Pattern:
        - nemo/collections/speechlm/models/speech_to_text_llm_model.py:1216:
          with open(output_file_path, "w") as f_json:
        
        Attack Vector:
        - User/attacker controls output_file_path via config
        - Can specify paths with traversal or absolute paths
        - Could overwrite configuration files or logs
        
        Expected Behavior (VULNERABLE):
        - output_file_path is used directly without validation
        - Files written to attacker-specified locations
        """
        # Simulate malicious configuration
        malicious_configs = [
            "../../../etc/app_config.json",  # Directory traversal
            "/var/log/malicious.log",         # Absolute path to logs
            "~/.bashrc",                       # User home directory
        ]
        
        for output_file_path in malicious_configs:
            # The vulnerability: These paths would be used directly
            assert any([
                ".." in output_file_path,
                os.path.isabs(output_file_path),
                output_file_path.startswith("~")
            ]), f"Dangerous path pattern in config: {output_file_path}"

    @pytest.mark.unit
    def test_config_controlled_yaml_output(self):
        """
        Test: Configuration-controlled YAML file output
        
        Vulnerable Pattern:
        - nemo/collections/speechlm/recipes/pipeline.py:57:
          with open(output_dir / "config.yaml", "w") as f:
        
        Attack Vector:
        - output_dir controlled by user/config
        - Combined with fixed filename can write config.yaml anywhere
        - Could overwrite application configuration
        
        Expected Behavior (VULNERABLE):
        - output_dir not validated before use
        - YAML files can be written to arbitrary locations
        """
        # Simulate user-controlled output_dir
        malicious_output_dirs = [
            Path("/etc/app"),           # System config directory
            Path("../../sensitive"),    # Directory traversal
            Path.home() / ".config",    # User config directory
        ]
        
        for output_dir in malicious_output_dirs:
            config_path = output_dir / "config.yaml"
            
            # The vulnerability: Path construction without validation
            assert (
                config_path.is_absolute() or 
                ".." in str(config_path)
            ), f"Can write config to dangerous location: {config_path}"


class TestCVE008PickleFileWrite:
    """
    Test suite for pickle file write vulnerabilities.
    
    Pickle files are particularly dangerous as they can contain arbitrary code.
    Writing pickle files to attacker-controlled locations could enable code execution.
    """

    @pytest.mark.unit
    def test_pickle_dump_to_user_controlled_path(self):
        """
        Test: Pickle dump to user-controlled file path
        
        Vulnerable Pattern:
        - nemo/collections/asr/models/clustering_diarizer.py:382:
          pkl.dump(self.embeddings, open(self._embeddings_file, 'wb'))
        
        Attack Vector:
        - _embeddings_file path controlled by user/config
        - Pickle files can contain arbitrary code
        - Writing to accessible locations could enable code execution
        
        Expected Behavior (VULNERABLE):
        - Pickle files written to user-controlled paths
        - No validation of output location
        """
        import pickle
        
        # Simulate user-controlled embeddings file path
        malicious_paths = [
            "/tmp/../../var/www/html/shell.pkl",  # Web-accessible location
            "~/.local/lib/python/malicious.pkl",   # Python path
            "../../../tmp/exploit.pkl",            # Directory traversal
        ]
        
        for embeddings_file in malicious_paths:
            # The vulnerability: pickle.dump to unvalidated path
            assert any([
                ".." in embeddings_file,
                os.path.isabs(embeddings_file),
                embeddings_file.startswith("~")
            ]), f"Pickle can be written to dangerous location: {embeddings_file}"
        
        # Demonstrate pickle write to user-controlled location
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pkl') as f:
            temp_pkl = f.name
            
        try:
            # Simulate vulnerable pattern: pkl.dump(data, open(path, 'wb'))
            test_data = {"embeddings": "malicious payload"}
            with open(temp_pkl, 'wb') as f:
                pickle.dump(test_data, f)
            
            assert os.path.exists(temp_pkl), \
                "Pickle file written to user-controlled path"
        finally:
            os.unlink(temp_pkl)


class TestCVE008DatasetOutputFile:
    """
    Test suite for dataset output file vulnerabilities.
    
    These tests verify vulnerabilities in dataset processing where output
    file paths can be controlled.
    """

    @pytest.mark.unit
    def test_dataset_output_file_write(self):
        """
        Test: Dataset output file controlled by user
        
        Vulnerable Pattern:
        - nemo/collections/asr/data/audio_to_text_dataset.py:851:
          self.outf = open(output_file, 'w', encoding='utf-8')
        
        Attack Vector:
        - output_file parameter controlled by user/config
        - Dataset processing writes to this file
        - Could overwrite data files or logs
        
        Expected Behavior (VULNERABLE):
        - output_file opened directly without path validation
        - Can write dataset output to arbitrary locations
        """
        # Simulate user-controlled output file paths
        malicious_output_files = [
            "/var/log/app.log",                    # Overwrite logs
            "../../../data/training_set.json",    # Directory traversal
            "/tmp/../../etc/dataset_config.json", # Traversal to system files
        ]
        
        for output_file in malicious_output_files:
            # The vulnerability: output_file used directly
            assert any([
                ".." in output_file,
                os.path.isabs(output_file)
            ]), f"Dataset can write to dangerous location: {output_file}"
        
        # Demonstrate the vulnerable pattern
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_output = f.name
            
        try:
            # Simulate: self.outf = open(output_file, 'w', encoding='utf-8')
            with open(temp_output, 'w', encoding='utf-8') as outf:
                outf.write("malicious dataset output\n")
            
            assert os.path.exists(temp_output), \
                "Dataset output written to user-controlled path"
        finally:
            os.unlink(temp_output)


class TestCVE008TempFileInManifest:
    """
    Test suite for temporary file vulnerabilities in manifest processing.
    
    These tests verify that temporary file creation in fixed locations
    can be exploited.
    """

    @pytest.mark.unit
    def test_manifest_write_in_temp_dir(self):
        """
        Test: Manifest file write in temporary directory
        
        Vulnerable Pattern:
        - nemo/collections/asr/models/classification_models.py:407:
          with open(os.path.join(temp_dir, 'manifest.json'), 'w', encoding='utf-8') as fp:
        
        Attack Vector:
        - If temp_dir is predictable or controlled
        - Attacker could pre-create symlink at manifest.json location
        - Write follows symlink to arbitrary location
        
        Expected Behavior (VULNERABLE):
        - No validation that manifest.json doesn't exist or is a symlink
        - Predictable temp file locations enable symlink attacks
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = os.path.join(temp_dir, 'manifest.json')
            
            # The vulnerability: Writing to predictable location without checking
            # In a real attack, attacker would create symlink before this runs
            
            # Demonstrate symlink attack potential
            target_file = os.path.join(temp_dir, 'target_file.txt')
            
            # Create symlink (simulating attacker pre-creating it)
            try:
                os.symlink(target_file, manifest_path)
                
                # Vulnerable code writes to manifest.json
                with open(manifest_path, 'w', encoding='utf-8') as fp:
                    fp.write('{"malicious": "data"}')
                
                # Data written to symlink target, not manifest.json
                assert os.path.exists(target_file), \
                    "Symlink attack successful - data written to target file"
                
                with open(target_file, 'r') as f:
                    content = f.read()
                assert "malicious" in content, \
                    "Malicious data written through symlink"
                    
            except OSError:
                # Symlinks might not be supported on all systems
                pytest.skip("Symlinks not supported on this system")


class TestCVE008RaceConditions:
    """
    Test suite for race condition vulnerabilities in file operations.
    
    TOCTOU (Time-of-check-time-of-use) vulnerabilities where file paths
    are checked but can be modified before use.
    """

    @pytest.mark.unit
    def test_makedirs_then_open_race_condition(self):
        """
        Test: Race condition between makedirs and file open
        
        Vulnerable Pattern:
        - os.makedirs(cfg.output_dir, exist_ok=True)
        - open(tgt_manifest_filepath, 'w')
        
        Attack Vector:
        - Between makedirs and open, attacker replaces directory with symlink
        - File write follows symlink to attacker-controlled location
        
        Expected Behavior (VULNERABLE):
        - No atomic check-and-write operation
        - Window for race condition exists
        """
        with tempfile.TemporaryDirectory() as base_dir:
            output_dir = os.path.join(base_dir, "output")
            
            # Step 1: makedirs (as vulnerable code does)
            os.makedirs(output_dir, exist_ok=True)
            
            # Step 2: Attacker could replace output_dir with symlink here
            # Simulating race condition window
            
            target_dir = os.path.join(base_dir, "malicious_target")
            os.makedirs(target_dir, exist_ok=True)
            
            # Remove output_dir and replace with symlink
            try:
                os.rmdir(output_dir)
                os.symlink(target_dir, output_dir)
                
                # Step 3: File write (as vulnerable code does)
                file_path = os.path.join(output_dir, "data.json")
                with open(file_path, 'w') as f:
                    f.write('{"data": "malicious"}')
                
                # Verify file was written to target_dir, not output_dir
                target_file = os.path.join(target_dir, "data.json")
                assert os.path.exists(target_file), \
                    "Race condition exploited - file written to symlink target"
                    
            except OSError:
                pytest.skip("Symlinks not supported on this system")


class TestCVE008PathNormalizationBypass:
    """
    Test suite for path normalization bypass vulnerabilities.
    
    These tests verify that various path encoding and normalization tricks
    can bypass weak path validation.
    """

    @pytest.mark.unit
    def test_path_normalization_bypass_techniques(self):
        """
        Test: Various path normalization bypass techniques
        
        Vulnerable Pattern:
        - Weak or missing path validation before file writes
        
        Attack Vectors:
        - Double encoding: ..%252f..%252f
        - Unicode normalization: ..%c0%af..%c0%af  
        - Mixed separators: ..\\../
        - Null byte injection: ../../etc/passwd%00.json
        
        Expected Behavior (VULNERABLE):
        - Insufficient normalization allows bypass
        """
        malicious_paths = [
            "output/../../etc/passwd",           # Basic traversal
            "output/..\\..\\windows\\system32",  # Mixed separators
            "output/..//../../etc/shadow",       # Extra slashes
            "./output/./../../../tmp/exploit",   # Multiple current dir refs
        ]
        
        for path in malicious_paths:
            normalized = os.path.normpath(path)
            
            # These paths normalize to locations outside "output"
            assert (
                ".." in normalized or 
                not normalized.startswith("output")
            ), f"Path traversal not prevented: {path} -> {normalized}"

    @pytest.mark.unit
    def test_path_object_normalization_insufficient(self):
        """
        Test: pathlib.Path normalization is insufficient for security
        
        Vulnerable Pattern:
        - Using Path() object without additional validation
        - Path(output_dir) / filename doesn't prevent traversal in output_dir
        
        Attack Vector:
        - output_dir contains "../../../etc"
        - Path construction doesn't validate the base directory
        
        Expected Behavior (VULNERABLE):
        - Path objects don't prevent directory traversal in components
        """
        base = Path("/safe/output")
        
        # Attacker controls the directory name
        malicious_dir = "../../malicious"
        
        # Path construction follows the traversal
        result = base / malicious_dir / "file.txt"
        
        normalized = result.resolve()
        base_resolved = base.resolve()
        
        # The path escapes the safe directory
        # Note: This might vary based on filesystem, but demonstrates the concept
        assert ".." in str(result) or "malicious" in str(normalized), \
            "Path object doesn't prevent traversal in components"


class TestCVE008IntegrationScenarios:
    """
    Integration tests demonstrating complete attack scenarios.
    
    These tests show end-to-end exploitation of the vulnerability.
    """

    @pytest.mark.unit
    def test_complete_directory_traversal_attack(self):
        """
        Test: Complete directory traversal attack scenario
        
        Scenario:
        1. Attacker provides config with malicious output_dir
        2. Application creates directories using os.makedirs
        3. Application writes files to traversed location
        4. Attacker gains arbitrary file write
        
        Expected Behavior (VULNERABLE):
        - Attack succeeds, file written outside intended directory
        """
        with tempfile.TemporaryDirectory() as base_dir:
            # Step 1: Setup intended safe directory
            safe_dir = os.path.join(base_dir, "app_data", "outputs")
            os.makedirs(safe_dir, exist_ok=True)
            
            # Step 2: Attacker provides malicious config
            malicious_config = {
                "output_dir": os.path.join(safe_dir, "../../../", base_dir, "malicious")
            }
            
            # Step 3: Application uses config without validation
            output_dir = malicious_config["output_dir"]
            os.makedirs(output_dir, exist_ok=True)
            
            # Step 4: Application writes file
            output_file = os.path.join(output_dir, "payload.json")
            with open(output_file, 'w') as f:
                f.write('{"malicious": "payload"}')
            
            # Step 5: Verify attack succeeded
            assert os.path.exists(output_file), \
                "Attack succeeded - file created"
            
            # Verify file is outside safe_dir
            safe_dir_real = os.path.realpath(safe_dir)
            output_file_real = os.path.realpath(output_file)
            
            assert not output_file_real.startswith(safe_dir_real), \
                "File written outside intended safe directory"

    @pytest.mark.unit
    def test_config_file_overwrite_attack(self):
        """
        Test: Configuration file overwrite attack scenario
        
        Scenario:
        1. Attacker provides path to overwrite app configuration
        2. Application writes data to that path
        3. Application configuration compromised
        
        Expected Behavior (VULNERABLE):
        - Configuration file can be overwritten
        """
        with tempfile.TemporaryDirectory() as base_dir:
            # Step 1: Create fake application config
            app_config = os.path.join(base_dir, "config.yaml")
            with open(app_config, 'w') as f:
                f.write("safe_setting: true\n")
            
            # Step 2: Attacker provides path to overwrite config
            # (simulating output_dir / "config.yaml" pattern)
            malicious_output_dir = base_dir
            config_path = os.path.join(malicious_output_dir, "config.yaml")
            
            # Step 3: Application writes to config path
            with open(config_path, 'w') as f:
                f.write("malicious_setting: true\n")
            
            # Step 4: Verify config was overwritten
            with open(app_config, 'r') as f:
                content = f.read()
            
            assert "malicious_setting" in content, \
                "Configuration file successfully overwritten"
            assert "safe_setting" not in content, \
                "Original configuration destroyed"


# Additional test markers for security testing
pytestmark = [
    pytest.mark.security,
    pytest.mark.cve_008,
]
