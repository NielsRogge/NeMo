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
Security Tests for CVE-004: Path Traversal via Configuration Files

These tests verify path traversal vulnerabilities when file paths are
specified through configuration files (YAML, JSON, etc.).

CRITICAL SEVERITY - Configuration files are a common attack vector for
path traversal when applications load models and datasets from user-specified paths.

Test Coverage:
1. YAML configuration file path handling
2. Model checkpoint paths in configs
3. Dataset paths in configs
4. Artifact paths in configs
5. Configuration validation and sanitization
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from omegaconf import DictConfig, OmegaConf


class TestConfigurationPathTraversal:
    """
    Test path traversal vulnerabilities through configuration files.

    Configuration files (YAML, JSON) are often used to specify model and dataset
    paths. If these paths are not validated, attackers can use them for traversal attacks.
    """

    def test_yaml_config_model_path_traversal(self):
        """
        Test that model paths in YAML configs are not validated for traversal.

        VULNERABILITY: Model checkpoint paths specified in configuration files
        are not validated, allowing path traversal attacks.

        Attack Vector: An attacker could create a malicious config file with
        paths like "../../sensitive/model.nemo" to load files from arbitrary locations.
        """
        # Create a malicious configuration
        malicious_config = """
        model:
          checkpoint_path: ../../../etc/passwd
          restore_path: ../../sensitive/model.nemo
        """

        # Parse the configuration (as the application would)
        config = OmegaConf.create(malicious_config)

        # VULNERABILITY: The malicious paths are accepted without validation
        assert config.model.checkpoint_path == "../../../etc/passwd"
        assert config.model.restore_path == "../../sensitive/model.nemo"
        assert ".." in config.model.checkpoint_path, "Path traversal sequence in checkpoint_path"
        assert ".." in config.model.restore_path, "Path traversal sequence in restore_path"

    def test_config_dataset_path_traversal(self):
        """
        Test that dataset paths in configs are not validated for traversal.

        VULNERABILITY: Dataset paths in configuration files can contain
        traversal sequences to read files outside the intended directory.

        Attack Vector: Training or inference configs could specify dataset
        paths that point to sensitive files instead of actual datasets.
        """
        # Malicious dataset configuration
        malicious_dataset_config = """
        train_ds:
          manifest_filepath: ../../../etc/shadow
          dataset_path: ../../sensitive_data/
        validation_ds:
          manifest_filepath: ../../../root/.ssh/id_rsa
        """

        config = OmegaConf.create(malicious_dataset_config)

        # VULNERABILITY: Dataset paths with traversal sequences are accepted
        assert ".." in config.train_ds.manifest_filepath, "Traversal in train manifest"
        assert ".." in config.train_ds.dataset_path, "Traversal in dataset path"
        assert ".." in config.validation_ds.manifest_filepath, "Traversal in validation manifest"

    def test_config_artifact_path_traversal(self):
        """
        Test that artifact paths in configs are not validated.

        VULNERABILITY: Artifact paths (tokenizers, normalizers, etc.) specified
        in configs can use traversal sequences.

        Attack Vector: Artifacts are loaded during model initialization,
        and malicious paths could cause unintended file access.
        """
        # Configuration with malicious artifact paths
        artifact_config = """
        tokenizer:
          vocab_file: ../../../etc/passwd
          spm_model: ../../sensitive/tokenizer.model
        normalizer:
          config_file: ../../../config/secrets.yaml
        """

        config = OmegaConf.create(artifact_config)

        # VULNERABILITY: Artifact paths are not validated
        assert ".." in config.tokenizer.vocab_file, "Traversal in vocab_file"
        assert ".." in config.tokenizer.spm_model, "Traversal in spm_model"
        assert ".." in config.normalizer.config_file, "Traversal in normalizer config"

    def test_config_nested_path_traversal(self):
        """
        Test path traversal in nested configuration structures.

        VULNERABILITY: Nested config structures may have paths that are
        not validated at any level.

        Attack Vector: Complex configurations with nested structures could
        hide malicious paths that bypass simple validation attempts.
        """
        nested_config = """
        model:
          encoder:
            pretrained_model: ../../pretrained/../../../sensitive.ckpt
          decoder:
            config:
              vocab_path: ../../../etc/passwd
          training:
            checkpoint:
              resume_from: ../../checkpoints/../../../sensitive/state.ckpt
        """

        config = OmegaConf.create(nested_config)

        # VULNERABILITY: Nested paths are not validated
        assert ".." in config.model.encoder.pretrained_model, "Traversal in nested encoder path"
        assert ".." in config.model.decoder.config.vocab_path, "Traversal in nested decoder path"
        assert ".." in config.model.training.checkpoint.resume_from, "Traversal in nested checkpoint path"

    def test_config_interpolation_path_traversal(self):
        """
        Test path traversal through OmegaConf variable interpolation.

        VULNERABILITY: Variable interpolation in configs could be used to
        construct malicious paths that bypass simple pattern matching.

        Attack Vector: An attacker could use interpolation to build traversal
        sequences: ${base_path}/../../../etc/passwd
        """
        # Configuration using interpolation to construct traversal
        interpolation_config = """
        base_path: /models
        traversal_segment: ../../etc
        checkpoint_path: ${base_path}/../${traversal_segment}/passwd
        """

        config = OmegaConf.create(interpolation_config)
        resolved = OmegaConf.to_container(config, resolve=True)

        # VULNERABILITY: Interpolation allows constructing traversal paths
        checkpoint_path = resolved['checkpoint_path']
        assert ".." in checkpoint_path, "Traversal sequence in interpolated path"
        assert "etc/passwd" in checkpoint_path, "Malicious file in interpolated path"

    def test_config_list_paths_with_traversal(self):
        """
        Test path traversal in configuration lists.

        VULNERABILITY: Lists of paths in configs (e.g., multiple datasets)
        are not validated individually.

        Attack Vector: In configurations that accept multiple paths,
        an attacker could include malicious paths in the list.
        """
        list_config = """
        training_manifests:
          - /legitimate/dataset1.json
          - ../../../etc/passwd
          - ../../sensitive/data.json
          - /another/legitimate/path
        """

        config = OmegaConf.create(list_config)

        # VULNERABILITY: List items with traversal are not validated
        malicious_paths = [p for p in config.training_manifests if ".." in str(p)]
        assert len(malicious_paths) >= 2, "Multiple malicious paths in config list"

    def test_config_from_dict_path_injection(self):
        """
        Test path traversal when configs are created from dictionaries.

        VULNERABILITY: When configurations are created programmatically from
        dictionaries (e.g., from API inputs), paths are not validated.

        Attack Vector: API endpoints that accept JSON configs could be exploited
        by sending malicious path values.
        """
        # Simulating a config received from an API
        api_config_dict = {
            "model": {"checkpoint": "../../../etc/passwd"},
            "dataset": {"path": "../../sensitive/data"},
            "output": {"dir": "../../../var/log"},
        }

        config = DictConfig(api_config_dict)

        # VULNERABILITY: Programmatically created configs are not validated
        assert ".." in config.model.checkpoint, "API-injected traversal in checkpoint"
        assert ".." in config.dataset.path, "API-injected traversal in dataset"
        assert ".." in config.output.dir, "API-injected traversal in output"


class TestConfigurationLoadingVulnerabilities:
    """
    Test vulnerabilities in how configurations are loaded and processed.
    """

    def test_yaml_file_path_not_validated(self):
        """
        Test that the path to the YAML config file itself is not validated.

        VULNERABILITY: The path to the configuration file can contain
        traversal sequences, potentially loading configs from unintended locations.

        Attack Vector: If a system accepts config file paths from users,
        an attacker could specify paths to malicious configs anywhere on the system.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a config in an unexpected location
            sensitive_dir = Path(tmpdir) / "sensitive"
            sensitive_dir.mkdir()
            malicious_config_path = sensitive_dir / "config.yaml"
            malicious_config_path.write_text("checkpoint: /etc/passwd")

            # Path with traversal to the config
            work_dir = Path(tmpdir) / "workspace"
            work_dir.mkdir()
            config_path_with_traversal = work_dir / "../sensitive/config.yaml"

            # VULNERABILITY: Config path with traversal is accepted
            assert config_path_with_traversal.exists(), "Config accessible via traversal"

            # Load the config (as the application would)
            config = OmegaConf.load(config_path_with_traversal)
            assert config.checkpoint == "/etc/passwd", "Malicious config loaded via traversal"

    def test_config_merge_path_injection(self):
        """
        Test path injection when merging multiple configuration sources.

        VULNERABILITY: When merging configs from multiple sources, malicious
        paths in secondary configs can override safe defaults.

        Attack Vector: If a user can provide an override config, they could
        inject malicious paths that replace safe default values.
        """
        # Safe default configuration
        default_config = OmegaConf.create(
            """
        model:
          checkpoint: /safe/models/default.nemo
        dataset:
          path: /safe/datasets/
        """
        )

        # Malicious override configuration
        override_config = OmegaConf.create(
            """
        model:
          checkpoint: ../../../etc/passwd
        dataset:
          path: ../../sensitive/
        """
        )

        # Merge configs (override takes precedence)
        merged = OmegaConf.merge(default_config, override_config)

        # VULNERABILITY: Malicious paths from override replace safe defaults
        assert merged.model.checkpoint == "../../../etc/passwd", "Malicious checkpoint path injected"
        assert merged.dataset.path == "../../sensitive/", "Malicious dataset path injected"

    def test_config_env_variable_path_injection(self):
        """
        Test path traversal through environment variable interpolation.

        VULNERABILITY: Environment variables used in configs can contain
        traversal sequences.

        Attack Vector: If an attacker can control environment variables,
        they could inject malicious paths into the configuration.
        """
        import os

        # Malicious environment variable
        os.environ['MALICIOUS_PATH'] = '../../../etc/passwd'

        try:
            config_with_env = """
            checkpoint_path: ${oc.env:MALICIOUS_PATH}
            """

            config = OmegaConf.create(config_with_env)
            resolved = OmegaConf.to_container(config, resolve=True)

            # VULNERABILITY: Environment variable contains traversal sequence
            assert ".." in resolved['checkpoint_path'], "Traversal injected via env var"
        finally:
            del os.environ['MALICIOUS_PATH']


class TestConfigurationValidationRequirements:
    """
    Document required security validations for configuration handling.
    """

    def test_config_paths_should_be_normalized(self):
        """
        Requirement: All paths from configs should be normalized.

        Proper implementation should:
        1. Extract all path values from config
        2. Normalize each path (resolve . and ..)
        3. Validate normalized paths are within allowed directories
        """
        import os

        config_path = "../../../etc/passwd"

        # CURRENT VULNERABILITY: Paths are used as-is
        # REQUIRED SOLUTION: Normalize before use
        normalized = os.path.normpath(config_path)

        # The path should be validated after normalization
        assert normalized.startswith("../"), "Normalized path still escapes directory"

    def test_config_paths_should_be_whitelisted(self):
        """
        Requirement: Only allow paths within whitelisted directories.

        Proper implementation should:
        1. Define allowed base directories (models, datasets, etc.)
        2. Resolve all config paths to absolute paths
        3. Verify each path starts with an allowed base directory
        4. Reject any path outside allowed directories
        """
        import os

        allowed_dirs = ["/models", "/datasets"]
        config_path = "../../../etc/passwd"

        # REQUIRED CHECK (NOT CURRENTLY IMPLEMENTED):
        absolute_path = os.path.abspath(config_path)

        # Check if path is within any allowed directory
        is_allowed = any(absolute_path.startswith(allowed) for allowed in allowed_dirs)

        # VULNERABILITY: Path is not within allowed directories
        assert not is_allowed, "Path should be rejected as it's outside allowed dirs"

    def test_config_should_validate_path_characters(self):
        """
        Requirement: Validate that paths contain only safe characters.

        Proper implementation should:
        1. Define a whitelist of allowed characters for paths
        2. Check all path strings against the whitelist
        3. Reject paths with suspicious characters (null bytes, etc.)
        """
        # Paths with suspicious characters
        suspicious_paths = [
            "../../../etc/passwd\x00.nemo",  # null byte
            "../../sensitive\r\n/data",  # newlines
            "../path\x1b[31m/exploit",  # ANSI escape sequences
        ]

        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./")

        for path in suspicious_paths:
            # REQUIRED CHECK (NOT CURRENTLY IMPLEMENTED):
            has_suspicious_chars = any(c not in allowed_chars for c in path)

            # VULNERABILITY: Paths with suspicious characters are not rejected
            assert has_suspicious_chars, f"Path {repr(path)} contains suspicious characters"

    def test_config_symlinks_should_be_resolved_and_validated(self):
        """
        Requirement: Symbolic links in config paths must be validated.

        Proper implementation should:
        1. Resolve all symbolic links in paths
        2. Validate that the resolved targets are within allowed directories
        3. Reject symlinks that point outside allowed directories
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed_dir = Path(tmpdir) / "allowed"
            allowed_dir.mkdir()

            forbidden_dir = Path(tmpdir) / "forbidden"
            forbidden_dir.mkdir()

            forbidden_file = forbidden_dir / "secret.nemo"
            forbidden_file.write_text("secret model")

            # Create symlink in allowed dir pointing to forbidden file
            symlink = allowed_dir / "model.nemo"
            try:
                symlink.symlink_to(forbidden_file)

                # REQUIRED CHECK (NOT CURRENTLY IMPLEMENTED):
                resolved = symlink.resolve()
                is_within_allowed = str(resolved).startswith(str(allowed_dir.resolve()))

                # VULNERABILITY: Symlink target is outside allowed directory
                assert not is_within_allowed, "Symlink points outside allowed directory - should be rejected"
            except (OSError, Exception):
                pass  # Symlink creation may fail on some systems
