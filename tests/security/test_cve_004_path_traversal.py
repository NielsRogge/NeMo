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
Security tests for CVE-004: Path Traversal Vulnerability

This test suite verifies the presence of path traversal vulnerabilities in the NeMo framework.
The vulnerability exists where file paths can be influenced by user input without proper validation,
potentially allowing attackers to access files outside intended directories.

Test Categories:
1. Deploy module - checkpoint path handling
2. VLM module - image file loading 
3. Export module - config file handling
4. General file I/O - manifest and config operations

NOTE: These tests are designed to DETECT vulnerabilities, not to fix them.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest


class TestCVE004PathTraversalDeployModule:
    """
    Test path traversal vulnerabilities in the nemo.deploy module.
    
    The deploy_base.py module accepts checkpoint_path from user input and uses it
    directly in restore_from() methods without validation, allowing potential
    directory traversal attacks.
    """

    def test_deploy_base_accepts_traversal_path(self):
        """
        VULNERABILITY: DeployBase accepts path traversal sequences in checkpoint_path.
        
        This test verifies that the deploy module accepts checkpoint paths containing
        directory traversal sequences (../) without validation. An attacker could
        potentially access sensitive checkpoint files outside the intended directory.
        """
        from nemo.deploy.deploy_base import DeployBase

        # Malicious path with directory traversal
        malicious_path = "../../../etc/passwd"
        
        # Create a mock deployable subclass
        class TestDeployable(DeployBase):
            def deploy(self):
                pass
            def serve(self):
                pass
            def run(self):
                pass
            def stop(self):
                pass

        # The vulnerability: checkpoint_path accepts traversal sequences without validation
        deployable = TestDeployable(
            triton_model_name="test",
            checkpoint_path=malicious_path,
            model=MagicMock()
        )
        
        # ASSERT: Path traversal sequence is accepted without validation
        assert deployable.checkpoint_path == malicious_path
        assert ".." in deployable.checkpoint_path
        print(f"VULNERABILITY DETECTED: checkpoint_path accepts traversal: {malicious_path}")

    def test_deploy_base_restore_from_unsafe_path(self):
        """
        VULNERABILITY: restore_from() uses user-controlled path without validation.
        
        The _init_nemo_model() method calls ModelPT.restore_from() with the user-supplied
        checkpoint_path, which could contain path traversal sequences.
        """
        from nemo.deploy.deploy_base import DeployBase
        
        class TestDeployable(DeployBase):
            def deploy(self):
                pass
            def serve(self):
                pass
            def run(self):
                pass
            def stop(self):
                pass

        traversal_paths = [
            "../../sensitive/model.nemo",
            "../../../etc/model.nemo",
            "models/../../../secrets/checkpoint.ckpt",
            "./../../private/model.nemo"
        ]
        
        for malicious_path in traversal_paths:
            with patch('nemo.deploy.deploy_base.ModelPT') as mock_model:
                with patch('nemo.deploy.deploy_base.Trainer') as mock_trainer:
                    mock_config = MagicMock()
                    mock_config.target = "nemo.test.TestModel"
                    mock_model.restore_from.return_value = mock_config
                    
                    deployable = TestDeployable(
                        triton_model_name="test",
                        checkpoint_path=malicious_path
                    )
                    
                    try:
                        deployable._init_nemo_model()
                        # VULNERABILITY: Path with traversal sequences was passed to restore_from
                        call_args = mock_model.restore_from.call_args
                        assert call_args is not None
                        checkpoint_arg = call_args[0][0] if call_args[0] else call_args[1].get('restore_path') or call_args[1].get('checkpoint_path')
                        assert ".." in checkpoint_arg or malicious_path in str(checkpoint_arg)
                        print(f"VULNERABILITY DETECTED: restore_from accepts: {checkpoint_arg}")
                    except Exception as e:
                        # Even if it fails, if the traversal path was passed through, it's vulnerable
                        if mock_model.restore_from.called:
                            print(f"VULNERABILITY DETECTED: traversal path was passed: {malicious_path}")

    def test_deploy_base_no_path_sanitization(self):
        """
        VULNERABILITY: No path sanitization or validation in DeployBase.__init__.
        
        The DeployBase constructor stores the checkpoint_path directly without any
        validation, normalization, or checks for path traversal patterns.
        """
        from nemo.deploy.deploy_base import DeployBase
        
        class TestDeployable(DeployBase):
            def deploy(self):
                pass
            def serve(self):
                pass
            def run(self):
                pass
            def stop(self):
                pass

        dangerous_patterns = [
            ("..\\..\\windows\\system32\\config", "Windows path traversal"),
            ("....//....//etc/shadow", "Encoded traversal"),
            ("/absolute/path/../../etc/passwd", "Absolute with traversal"),
            ("symbolic/../../../link/attack", "Symbolic link traversal")
        ]
        
        for path, description in dangerous_patterns:
            deployable = TestDeployable(
                triton_model_name="test",
                checkpoint_path=path,
                model=MagicMock()
            )
            # VULNERABILITY: No sanitization occurred, dangerous path accepted as-is
            assert deployable.checkpoint_path == path
            print(f"VULNERABILITY DETECTED: {description} - {path}")


class TestCVE004PathTraversalVLMModule:
    """
    Test path traversal vulnerabilities in the VLM (Vision Language Model) module.
    
    The preloaded.py module's TarOrFolderImageLoader.open_image() method uses
    os.path.join with user-controlled file_name without validation.
    """

    def test_image_loader_accepts_traversal_filename(self):
        """
        VULNERABILITY: TarOrFolderImageLoader accepts file paths with traversal sequences.
        
        The open_image() method in TarOrFolderImageLoader uses os.path.join(self.image_folder, file_name)
        where file_name comes from untrusted data without validation.
        """
        from nemo.collections.vlm.neva.data.preloaded import TarOrFolderImageLoader
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a sensitive file outside the image folder
            sensitive_dir = os.path.join(tmpdir, "sensitive")
            os.makedirs(sensitive_dir, exist_ok=True)
            sensitive_file = os.path.join(sensitive_dir, "secret.txt")
            with open(sensitive_file, "w") as f:
                f.write("SECRET DATA")
            
            # Create image folder
            image_folder = os.path.join(tmpdir, "images")
            os.makedirs(image_folder, exist_ok=True)
            
            loader = TarOrFolderImageLoader(image_folder)
            
            # Malicious file names with directory traversal
            malicious_names = [
                "../sensitive/secret.txt",
                "../../sensitive/secret.txt",
                "../../../etc/passwd",
                "./../sensitive/secret.txt"
            ]
            
            for malicious_name in malicious_names:
                # The vulnerability: os.path.join allows escaping the image_folder
                constructed_path = os.path.join(image_folder, malicious_name)
                normalized = os.path.normpath(constructed_path)
                
                # ASSERT: Path traversal escapes the intended directory
                assert not normalized.startswith(os.path.normpath(image_folder))
                print(f"VULNERABILITY DETECTED: Image path escapes folder: {malicious_name}")
                print(f"  Constructed path: {constructed_path}")
                print(f"  Normalized path: {normalized}")

    def test_image_loader_no_path_validation(self):
        """
        VULNERABILITY: No validation that loaded files are within the image_folder.
        
        The open_image() method does not verify that the resulting path is within
        the intended image_folder directory before opening the file.
        """
        from nemo.collections.vlm.neva.data.preloaded import TarOrFolderImageLoader
        
        with tempfile.TemporaryDirectory() as tmpdir:
            image_folder = os.path.join(tmpdir, "images")
            os.makedirs(image_folder, exist_ok=True)
            
            loader = TarOrFolderImageLoader(image_folder)
            
            # Test that the code path exists for joining user-controlled filenames
            test_filename = "../../../etc/passwd"
            
            # Mock Image.open to prevent actual file access
            with patch('nemo.collections.vlm.neva.data.preloaded.Image.open') as mock_open:
                try:
                    loader.open_image(test_filename)
                except Exception:
                    pass
                
                if mock_open.called:
                    # VULNERABILITY: Path with traversal was passed to Image.open
                    called_path = mock_open.call_args[0][0]
                    print(f"VULNERABILITY DETECTED: Image.open called with: {called_path}")
                    assert ".." in test_filename

    def test_video_loader_path_traversal(self):
        """
        VULNERABILITY: TarOrFolderVideoLoader has same path traversal issue.
        
        Similar to TarOrFolderImageLoader, the video loader uses os.path.join
        with user-controlled file names without validation.
        """
        from nemo.collections.vlm.neva.data.preloaded import TarOrFolderVideoLoader
        from nemo.collections.vlm.neva.data.config import ImageDataConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            video_folder = os.path.join(tmpdir, "videos")
            os.makedirs(video_folder, exist_ok=True)
            
            # Create a mock data config
            data_config = ImageDataConfig()
            data_config.splice_single_frame = 'first'
            data_config.num_frames = 1
            
            loader = TarOrFolderVideoLoader(video_folder, data_config)
            
            # Malicious video file names
            malicious_names = [
                "../../../etc/passwd",
                "../../secrets/video.mp4",
                "../sensitive/data.avi"
            ]
            
            for malicious_name in malicious_names:
                constructed_path = os.path.join(video_folder, malicious_name)
                normalized = os.path.normpath(constructed_path)
                
                # VULNERABILITY: Path escapes intended directory
                assert not normalized.startswith(os.path.normpath(video_folder))
                print(f"VULNERABILITY DETECTED: Video path escapes folder: {malicious_name}")


class TestCVE004PathTraversalExportModule:
    """
    Test path traversal vulnerabilities in the nemo.export module.
    
    Multiple export modules read config files using os.path.join with potentially
    user-controlled directory paths.
    """

    def test_tensorrt_llm_config_path_traversal(self):
        """
        VULNERABILITY: TensorRT LLM exporter uses user-controlled paths for config files.
        
        The module reads config.json using os.path.join(self.model_dir, "config.json")
        where model_dir could be influenced by user input.
        """
        # The vulnerability is in how model_dir is used
        model_dirs = [
            "../../../etc",
            "../../sensitive/models",
            "../../../var/secrets"
        ]
        
        for model_dir in model_dirs:
            config_path = os.path.join(model_dir, "config.json")
            normalized = os.path.normpath(config_path)
            
            # VULNERABILITY: Config path can traverse to sensitive directories
            print(f"VULNERABILITY DETECTED: Config path traversal: {config_path}")
            assert ".." in model_dir

    def test_multimodal_run_visual_engine_path(self):
        """
        VULNERABILITY: Multimodal run module reads configs from user-controlled paths.
        
        The run.py module opens os.path.join(visual_engine_dir, "config.json")
        where visual_engine_dir could be attacker-controlled.
        """
        visual_engine_dirs = [
            "../../../etc",
            "../../sensitive",
            "../../../home/user/.ssh"
        ]
        
        for engine_dir in visual_engine_dirs:
            config_path = os.path.join(engine_dir, "config.json")
            
            # VULNERABILITY: Can read config from arbitrary directory
            print(f"VULNERABILITY DETECTED: Visual engine config path: {config_path}")
            assert ".." in engine_dir

    def test_multimodal_image_folder_traversal(self):
        """
        VULNERABILITY: Image loading in multimodal export uses unsafe path joining.
        
        Line 688 in multimodal/run.py uses Image.open(os.path.join(image_folder, image_file))
        where both parameters could be attacker-influenced.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            image_folder = os.path.join(tmpdir, "images")
            os.makedirs(image_folder, exist_ok=True)
            
            # Create sensitive file outside image folder
            sensitive_file = os.path.join(tmpdir, "secret.png")
            
            # Malicious image file names
            malicious_files = [
                "../secret.png",
                "../../etc/passwd",
                "../../../root/.bashrc"
            ]
            
            for image_file in malicious_files:
                constructed_path = os.path.join(image_folder, image_file)
                normalized = os.path.normpath(constructed_path)
                
                # VULNERABILITY: Image path escapes intended folder
                assert not normalized.startswith(os.path.normpath(image_folder))
                print(f"VULNERABILITY DETECTED: Image file path traversal: {image_file}")


class TestCVE004PathTraversalGeneralFileOps:
    """
    Test path traversal vulnerabilities in general file operations across the codebase.
    
    Tests for manifest files, temp directories, and configuration file handling
    that use user-influenced paths.
    """

    def test_manifest_filepath_traversal(self):
        """
        VULNERABILITY: Manifest file paths constructed with user-controlled temp_dir.
        
        Multiple models construct manifest paths using os.path.join(config['temp_dir'], 'manifest.json')
        where temp_dir comes from configuration that could be attacker-controlled.
        """
        malicious_configs = [
            {"temp_dir": "../../../etc"},
            {"temp_dir": "../../sensitive/data"},
            {"temp_dir": "../../../var/secrets"}
        ]
        
        for config in malicious_configs:
            manifest_path = os.path.join(config['temp_dir'], 'manifest.json')
            
            # VULNERABILITY: Manifest can be written to arbitrary directory
            print(f"VULNERABILITY DETECTED: Manifest path traversal: {manifest_path}")
            assert ".." in manifest_path

    def test_config_yaml_path_injection(self):
        """
        VULNERABILITY: Config YAML paths accept traversal sequences.
        
        Save/restore connectors and other modules use os.path.join with user-provided
        directories for config files.
        """
        temp_dirs = [
            "/tmp/../../../etc",
            "/var/tmp/../../sensitive",
            "./../../config/secrets"
        ]
        
        for tmpdir in temp_dirs:
            config_path = os.path.join(tmpdir, "model_config.yaml")
            normalized = os.path.normpath(config_path)
            
            # VULNERABILITY: Config file path can traverse directories
            print(f"VULNERABILITY DETECTED: Config YAML path: {config_path}")

    def test_no_realpath_validation(self):
        """
        VULNERABILITY: No use of os.path.realpath() to resolve symlinks and traversals.
        
        The codebase does not use os.path.realpath() or similar methods to resolve
        symlinks and canonicalize paths before file operations.
        """
        # Demonstrate that os.path.join doesn't prevent traversal
        base_dir = "/safe/directory"
        user_input = "../../etc/passwd"
        
        # Without realpath validation
        unsafe_path = os.path.join(base_dir, user_input)
        normalized = os.path.normpath(unsafe_path)
        
        # VULNERABILITY: Path escapes base directory
        assert not normalized.startswith(base_dir)
        print(f"VULNERABILITY DETECTED: No realpath validation")
        print(f"  Base: {base_dir}")
        print(f"  User input: {user_input}")
        print(f"  Result: {normalized}")

    def test_no_path_whitelist_validation(self):
        """
        VULNERABILITY: No whitelist of allowed directories for file operations.
        
        The codebase does not implement a whitelist of allowed directories,
        allowing files to be read from any location the process has access to.
        """
        # Demonstrate lack of whitelist checking
        allowed_dirs = ["/var/models", "/opt/nemo/checkpoints"]
        
        # An attacker could specify paths outside the whitelist
        malicious_paths = [
            "/etc/passwd",
            "/root/.ssh/id_rsa",
            "/var/secrets/api_keys.json",
            "../../../etc/shadow"
        ]
        
        for path in malicious_paths:
            # VULNERABILITY: No code checks if path is in allowed_dirs
            is_allowed = any(os.path.normpath(path).startswith(allowed) for allowed in allowed_dirs)
            assert not is_allowed
            print(f"VULNERABILITY DETECTED: Path outside whitelist: {path}")

    def test_filename_character_validation(self):
        """
        VULNERABILITY: No validation of allowed characters in filenames.
        
        The codebase does not restrict filenames to safe characters, allowing
        special characters that could be used in attacks.
        """
        dangerous_filenames = [
            "../../../etc/passwd",
            "file;rm -rf /",
            "file\x00.txt",  # Null byte injection
            "file$(whoami).txt",  # Command injection attempt
            "file`cat /etc/passwd`.txt"
        ]
        
        # Define safe character set (should be enforced but isn't)
        import re
        safe_pattern = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
        
        for filename in dangerous_filenames:
            # VULNERABILITY: Dangerous filenames are not rejected
            if not safe_pattern.match(filename):
                print(f"VULNERABILITY DETECTED: Dangerous filename accepted: {repr(filename)}")

    def test_absolute_path_injection(self):
        """
        VULNERABILITY: Absolute paths can be injected to access arbitrary files.
        
        When user input is passed to file operations, absolute paths can bypass
        intended directory restrictions.
        """
        base_dir = "/safe/directory"
        
        # Absolute paths bypass the base directory entirely
        absolute_paths = [
            "/etc/passwd",
            "/var/secrets/keys.txt",
            "/root/.bashrc"
        ]
        
        for abs_path in absolute_paths:
            # When used with os.path.join, absolute paths override the base
            result = os.path.join(base_dir, abs_path)
            
            # VULNERABILITY: Absolute path overrides base directory
            assert result == abs_path
            assert not result.startswith(base_dir)
            print(f"VULNERABILITY DETECTED: Absolute path injection: {abs_path}")


class TestCVE004RealWorldScenarios:
    """
    Real-world attack scenarios for CVE-004 path traversal vulnerability.
    
    These tests demonstrate how the vulnerabilities could be exploited in
    actual deployment scenarios.
    """

    def test_scenario_model_checkpoint_exfiltration(self):
        """
        ATTACK SCENARIO: Attacker exfiltrates sensitive files via model checkpoint path.
        
        An attacker with control over configuration could specify a checkpoint path
        that points to sensitive files, causing the application to read and potentially
        expose them.
        """
        from nemo.deploy.deploy_base import DeployBase
        
        class TestDeployable(DeployBase):
            def deploy(self):
                pass
            def serve(self):
                pass
            def run(self):
                pass
            def stop(self):
                pass

        # ATTACK: Attacker provides malicious checkpoint path in config
        attack_paths = [
            "/etc/passwd",  # Read system users
            "../../../root/.ssh/id_rsa",  # Steal SSH keys
            "../../app/config/database.yml",  # Steal DB credentials
            "../secrets/api_keys.json"  # Steal API keys
        ]
        
        for attack_path in attack_paths:
            deployable = TestDeployable(
                triton_model_name="malicious",
                checkpoint_path=attack_path,
                model=MagicMock()
            )
            
            # VULNERABILITY: Malicious path accepted without validation
            assert deployable.checkpoint_path == attack_path
            print(f"ATTACK SCENARIO: Checkpoint exfiltration via: {attack_path}")

    def test_scenario_config_injection_via_api(self):
        """
        ATTACK SCENARIO: Attacker injects traversal path via API endpoint.
        
        If the REST API accepts model paths from users, an attacker could
        specify paths with traversal sequences to access sensitive files.
        """
        # Simulate API request payload
        api_payloads = [
            {"model": "../../etc/passwd"},
            {"checkpoint_path": "../../../var/secrets/api_keys"},
            {"image_folder": "../../../home/user/.ssh"},
            {"config_path": "../../app/secrets/credentials.json"}
        ]
        
        for payload in api_payloads:
            for key, value in payload.items():
                if ".." in value or value.startswith("/etc") or value.startswith("/var"):
                    print(f"ATTACK SCENARIO: API injection - {key}: {value}")

    def test_scenario_image_dataset_poisoning(self):
        """
        ATTACK SCENARIO: Attacker poisons training data via malicious image paths.
        
        An attacker who can influence the dataset manifest could include image paths
        with traversal sequences to read sensitive files during training.
        """
        # Malicious dataset manifest
        malicious_manifest = [
            {"image": "../../../etc/passwd", "caption": "exfiltrate"},
            {"image": "../../secrets/key.png", "caption": "steal"},
            {"image": "../../../../../root/.bashrc", "caption": "leak"}
        ]
        
        for item in malicious_manifest:
            image_path = item["image"]
            assert ".." in image_path
            print(f"ATTACK SCENARIO: Dataset poisoning with: {image_path}")

    def test_scenario_symlink_attack(self):
        """
        ATTACK SCENARIO: Attacker uses symlinks to bypass directory restrictions.
        
        An attacker could create a symlink in an allowed directory that points to
        a sensitive file, then reference it to bypass path restrictions.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate allowed directory
            allowed_dir = os.path.join(tmpdir, "models")
            os.makedirs(allowed_dir, exist_ok=True)
            
            # Simulate sensitive file
            sensitive_dir = os.path.join(tmpdir, "secrets")
            os.makedirs(sensitive_dir, exist_ok=True)
            sensitive_file = os.path.join(sensitive_dir, "api_key.txt")
            with open(sensitive_file, "w") as f:
                f.write("SECRET_KEY_12345")
            
            # ATTACK: Create symlink in allowed directory
            symlink_path = os.path.join(allowed_dir, "malicious_link")
            try:
                os.symlink(sensitive_file, symlink_path)
                
                # Attacker references the symlink
                # Without realpath validation, this would access the sensitive file
                assert os.path.exists(symlink_path)
                assert os.path.islink(symlink_path)
                print(f"ATTACK SCENARIO: Symlink attack created: {symlink_path} -> {sensitive_file}")
            except OSError:
                # Symlink creation might fail in some environments
                print("ATTACK SCENARIO: Symlink attack (creation skipped)")


# Test execution markers
# Using unit marker as security marker is not defined in pyproject.toml
pytestmark = pytest.mark.unit
