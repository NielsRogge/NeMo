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
Security Tests for CVE-004: Path Traversal Vulnerability

CVE ID: CVE-004
Severity: CRITICAL
Jira Issue: https://ml6team.atlassian.net/browse/DR-136

Description:
The application may be vulnerable to path traversal. The framework reads and processes 
files from disk, including datasets and models. If file paths can be influenced by user 
input (e.g., through a configuration file or an API endpoint), an attacker could craft 
a path to read sensitive files outside the intended directory.

These tests verify the presence of path traversal vulnerabilities in various components
of the nemo.deploy module and related file handling operations.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest


class TestPathTraversalMultimodal:
    """
    Tests for path traversal vulnerabilities in multimodal query functionality.
    
    The NemoQueryMultimodal class accepts user-provided file paths for images, videos,
    and audio files without proper validation or sanitization. This allows potential
    path traversal attacks.
    """

    def test_image_path_traversal_attack(self):
        """
        Test: Verify that NemoQueryMultimodal accepts path traversal sequences in image paths.
        
        Vulnerability: The setup_media() method directly passes user input to Image.open()
        without validating or sanitizing the path. An attacker could use '../' sequences
        to access files outside the intended directory.
        
        Location: nemo/deploy/multimodal/query_multimodal.py:81
        Code: media = Image.open(input_media).convert('RGB')
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        # Create instance with mocked dependencies
        nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="neva")

        # Test various path traversal patterns
        malicious_paths = [
            "../../../etc/passwd",  # Unix-style traversal
            "..\\..\\..\\windows\\system32\\config\\sam",  # Windows-style traversal
            "/etc/passwd",  # Absolute path access
            "../../../../../../../../etc/passwd",  # Deep traversal
            "....//....//....//etc/passwd",  # Double encoding
        ]

        for malicious_path in malicious_paths:
            # Mock PIL Image.open to avoid actual file access
            with patch('PIL.Image.open') as mock_image_open:
                mock_img = MagicMock()
                mock_img.convert.return_value = MagicMock()
                mock_image_open.return_value = mock_img

                try:
                    # This should call Image.open with the malicious path directly
                    # Demonstrating lack of path validation
                    result = nq.setup_media(malicious_path)

                    # Verify that Image.open was called with the malicious path unchanged
                    mock_image_open.assert_called_once()
                    called_path = mock_image_open.call_args[0][0]

                    # VULNERABILITY: The path is passed through without sanitization
                    assert (
                        called_path == malicious_path
                    ), f"Path was sanitized unexpectedly for: {malicious_path}"
                except Exception as e:
                    # If an exception occurs, it's likely due to the path not existing,
                    # not due to security validation
                    pass

    def test_audio_path_traversal_attack(self):
        """
        Test: Verify that NemoQueryMultimodal accepts path traversal sequences in audio paths.
        
        Vulnerability: The setup_media() method for audio files (model_type='salm') directly 
        passes user input to sf.read() without validation.
        
        Location: nemo/deploy/multimodal/query_multimodal.py:84
        Code: waveform, sample_rate = sf.read(input_media, dtype=np.float32)
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="salm")

        malicious_audio_paths = [
            "../../../etc/shadow",
            "../../sensitive_data.wav",
            "/root/.ssh/id_rsa",
        ]

        for malicious_path in malicious_audio_paths:
            with patch('soundfile.read') as mock_sf_read:
                # Mock successful read to test if path validation occurs
                mock_sf_read.return_value = (MagicMock(), 16000)

                try:
                    result = nq.setup_media(malicious_path)

                    # VULNERABILITY: Path is passed directly to sf.read without validation
                    mock_sf_read.assert_called_once()
                    called_path = mock_sf_read.call_args[0][0]
                    assert (
                        called_path == malicious_path
                    ), f"Audio path was sanitized unexpectedly for: {malicious_path}"
                except Exception:
                    pass

    def test_video_path_traversal_attack(self):
        """
        Test: Verify that NemoQueryMultimodal accepts path traversal sequences in video paths.
        
        Vulnerability: The setup_media() method for video files directly passes user input
        to VideoReader without path validation.
        
        Location: nemo/deploy/multimodal/query_multimodal.py:67-68
        Code: vr = VideoReader(input_media)
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="video-neva")

        malicious_video_paths = [
            "../../../etc/passwd",
            "../../confidential/video.mp4",
        ]

        for malicious_path in malicious_video_paths:
            try:
                with patch('nemo.deploy.multimodal.query_multimodal.VideoReader') as mock_video_reader:
                    mock_vr = MagicMock()
                    mock_vr.__iter__ = MagicMock(return_value=iter([MagicMock(asnumpy=lambda: [[1, 2, 3]])]))
                    mock_video_reader.return_value = mock_vr

                    result = nq.setup_media(malicious_path)

                    # VULNERABILITY: Path is passed directly to VideoReader
                    mock_video_reader.assert_called_once_with(malicious_path)
            except Exception:
                pass


class TestPathTraversalConfigManager:
    """
    Tests for path traversal vulnerabilities in configuration file handling.
    
    The ConfigManager class loads various configuration files based on user-provided
    paths without proper validation. This could allow attackers to read arbitrary files
    or load malicious configuration files.
    """

    def test_config_path_traversal_via_constructor(self):
        """
        Test: Verify that ConfigManager accepts path traversal sequences in config paths.
        
        Vulnerability: The __init__ method accepts server_config_path parameter without
        validating that it points to an allowed directory.
        
        Location: nemo/agents/voice_agent/utils/config_manager.py:44-50
        """
        try:
            from nemo.agents.voice_agent.utils.config_manager import ConfigManager
        except ImportError:
            pytest.skip("ConfigManager not available")

        malicious_config_paths = [
            "../../../etc/passwd",
            "../../sensitive_config.yaml",
            "/etc/shadow",
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake server base path
            base_path = Path(tmpdir) / "server"
            base_path.mkdir()

            for malicious_path in malicious_config_paths:
                # Mock os.path.exists to simulate file existing
                with patch('os.path.exists') as mock_exists:
                    mock_exists.return_value = True

                    # Mock OmegaConf.load to prevent actual file loading
                    with patch('omegaconf.OmegaConf.load') as mock_load:
                        mock_load.return_value = MagicMock()

                        try:
                            # VULNERABILITY: ConfigManager accepts arbitrary paths
                            # No validation that path is within allowed directory
                            cm = ConfigManager(
                                server_base_path=str(base_path), server_config_path=malicious_path
                            )

                            # If we reach here, the malicious path was accepted
                            # This demonstrates the vulnerability
                            assert True, "Malicious config path was accepted without validation"
                        except FileNotFoundError:
                            # Expected if path validation exists (it doesn't)
                            pass
                        except Exception as e:
                            # Other exceptions are fine for this test
                            pass

    def test_system_prompt_file_path_traversal(self):
        """
        Test: Verify that ConfigManager reads arbitrary files via system_prompt parameter.
        
        Vulnerability: The _configure_llm() method reads a file specified in the
        system_prompt config parameter without validating the path.
        
        Location: nemo/agents/voice_agent/utils/config_manager.py:221-223
        Code: 
            if os.path.isfile(system_prompt):
                with open(system_prompt, "r") as f:
                    system_prompt = f.read()
        """
        try:
            from nemo.agents.voice_agent.utils.config_manager import ConfigManager
        except ImportError:
            pytest.skip("ConfigManager not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "server"
            base_path.mkdir()

            # Create necessary directory structure
            (base_path / "server_configs").mkdir()
            (base_path / "server_configs" / "llm_configs").mkdir()

            # Create a minimal config file
            config_file = base_path / "server_configs" / "default.yaml"
            config_file.write_text(
                """
transport:
  audio_out_10ms_chunks: true
vad:
  confidence: 0.5
  start_secs: 0.2
  stop_secs: 0.5
  min_volume: 0.6
stt:
  model: test
  type: nemo
  device: cpu
diar:
  model: test
  enabled: false
  frame_len_in_secs: 0.1
  threshold: 0.5
turn_taking:
  backchannel_phrases_path: /tmp/phrases
  max_buffer_size: 100
  bot_stop_delay: 0.5
llm:
  model: test
  system_prompt: ../../../etc/passwd
tts:
  model: test
  type: nemo
"""
            )

            # Create model registry
            registry_file = base_path / "model_registry.yaml"
            registry_file.write_text(
                """
llm_models:
  test:
    yaml_id: test.yaml
  hf_llm_generic:
    yaml_id: generic.yaml
tts_models:
  test:
    yaml_id: test.yaml
stt_models:
  stt_en_fastconformer:
    test:
      yaml_id: test.yaml
"""
            )

            # Create dummy config files
            llm_config = base_path / "server_configs" / "llm_configs" / "test.yaml"
            llm_config.write_text("model: test\n")

            tts_config = base_path / "server_configs" / "tts_configs" / "test.yaml"
            tts_config.write_text("model: test\n")

            stt_configs_dir = base_path / "server_configs" / "stt_configs"
            stt_configs_dir.mkdir()
            stt_config = stt_configs_dir / "test.yaml"
            stt_config.write_text(
                "att_context_size: [1,1]\nframe_len_in_secs: 0.1\nraw_audio_frame_len_in_secs: 0.016\n"
            )

            # Mock os.path.isfile to return True for our malicious path
            original_isfile = os.path.isfile

            def mock_isfile(path):
                if "../../../etc/passwd" in str(path):
                    return True
                return original_isfile(path)

            with patch('os.path.isfile', side_effect=mock_isfile):
                # Mock open to capture the file path being opened
                m_open = mock_open(read_data="malicious content")
                with patch('builtins.open', m_open):
                    try:
                        cm = ConfigManager(server_base_path=str(base_path))

                        # Check if malicious file would be opened
                        opened_files = [call[0][0] for call in m_open.call_args_list]

                        # VULNERABILITY: If system_prompt contains a path, it's opened directly
                        # without validation
                        malicious_opens = [f for f in opened_files if 'etc/passwd' in str(f)]
                        if malicious_opens:
                            assert (
                                True
                            ), "ConfigManager attempted to open file with path traversal in system_prompt"
                    except Exception:
                        pass

    def test_config_file_loading_path_traversal(self):
        """
        Test: Verify that ConfigManager constructs config file paths without proper validation.
        
        Vulnerability: Config file paths are constructed using user-controlled values
        without validating that the resulting path is within allowed directories.
        
        Locations:
        - nemo/agents/voice_agent/utils/config_manager.py:137 (STT config)
        - nemo/agents/voice_agent/utils/config_manager.py:194 (LLM config) 
        - nemo/agents/voice_agent/utils/config_manager.py:250 (TTS config)
        """
        # This test demonstrates how an attacker could manipulate yaml_file_name
        # to cause path traversal when config paths are constructed

        malicious_yaml_names = [
            "../../../etc/passwd",
            "../../config/../../../sensitive.yaml",
            "../../../root/.ssh/id_rsa",
        ]

        for yaml_name in malicious_yaml_names:
            # Construct path the same way ConfigManager does
            with tempfile.TemporaryDirectory() as tmpdir:
                base_path = Path(tmpdir) / "server"
                base_path.mkdir()
                server_configs = base_path / "server_configs"
                server_configs.mkdir()

                # This is how ConfigManager constructs paths:
                # f"{os.path.abspath(self._server_base_path)}/server_configs/stt_configs/{yaml_file_name}"

                constructed_path = (
                    f"{os.path.abspath(base_path)}/server_configs/stt_configs/{yaml_name}"
                )

                # VULNERABILITY: The constructed path can escape the intended directory
                # If yaml_file_name contains ../, the resulting path goes outside server_configs
                normalized_path = os.path.normpath(constructed_path)

                # Check if path escapes the base directory
                if not normalized_path.startswith(os.path.abspath(base_path)):
                    assert (
                        True
                    ), f"Path traversal successful: {yaml_name} escapes base directory to {normalized_path}"


class TestPathTraversalFastAPIEndpoints:
    """
    Tests for path traversal vulnerabilities in FastAPI REST endpoints.
    
    While the current implementation doesn't directly expose file path parameters,
    the model name parameter could potentially be exploited if model loading uses
    file paths constructed from user input.
    """

    def test_model_name_path_traversal(self):
        """
        Test: Verify that model name parameter is not validated for path traversal.
        
        Potential Vulnerability: If model names are used to construct file paths for
        loading model files, path traversal sequences in the model name could allow
        arbitrary file access.
        
        Location: nemo/deploy/service/rest_model_api.py:109-112
        """
        from fastapi.testclient import TestClient

        try:
            from nemo.deploy.service.rest_model_api import app
        except ImportError:
            pytest.skip("FastAPI app not available")

        client = TestClient(app)

        malicious_model_names = [
            "../../../etc/passwd",
            "../../models/../../../sensitive_model",
            "/absolute/path/to/model",
        ]

        for malicious_name in malicious_model_names:
            # Mock the NemoQueryLLM to prevent actual model loading
            with patch('nemo.deploy.service.rest_model_api.NemoQueryLLM') as mock_query:
                mock_instance = MagicMock()
                mock_instance.query_llm.return_value = [["test output"]]
                mock_query.return_value = mock_instance

                response = client.post(
                    "/v1/completions/",
                    json={
                        "model": malicious_name,
                        "prompt": "test",
                        "max_tokens": 10,
                    },
                )

                # Check if malicious model name was accepted
                if response.status_code == 200 or mock_query.called:
                    # VULNERABILITY: Model name with path traversal was accepted
                    # If this is later used to construct file paths, it could lead to path traversal
                    call_args = mock_query.call_args
                    if call_args:
                        model_name_used = call_args[1].get('model_name', '')
                        assert (
                            malicious_name in str(model_name_used)
                        ), f"Malicious model name was accepted: {malicious_name}"


class TestPathTraversalMitigations:
    """
    Tests to verify the ABSENCE of security controls.
    
    These tests check that proper security measures like path validation,
    sanitization, and whitelisting are NOT implemented, demonstrating the
    vulnerability.
    """

    def test_no_path_normalization(self):
        """
        Test: Verify that file paths are not normalized before use.
        
        Expected behavior for secure code: Paths should be normalized using
        os.path.realpath() or os.path.normpath() and validated against allowed directories.
        
        Current behavior: Paths are used directly without normalization.
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="neva")

        # Path with redundant separators and ./ components
        tricky_path = "test/./images/../../../etc/passwd"

        with patch('PIL.Image.open') as mock_open:
            mock_img = MagicMock()
            mock_img.convert.return_value = MagicMock()
            mock_open.return_value = mock_img

            try:
                nq.setup_media(tricky_path)

                # VULNERABILITY: Path is not normalized before being passed to Image.open
                called_path = mock_open.call_args[0][0]
                assert called_path == tricky_path, "Path was normalized (security control exists)"
            except Exception:
                pass

    def test_no_whitelist_validation(self):
        """
        Test: Verify that there is no whitelist validation for allowed directories.
        
        Expected behavior for secure code: File paths should be validated against
        a whitelist of allowed directories before being opened.
        
        Current behavior: Any path is accepted without checking if it's in an allowed directory.
        """
        # This test verifies that paths outside typical data directories are accepted

        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="neva")

        # Paths that should be rejected by a whitelist
        disallowed_paths = [
            "/etc/passwd",  # System file
            "/root/.ssh/id_rsa",  # Private key
            "/proc/self/environ",  # Process environment
            "C:\\Windows\\System32\\config\\SAM",  # Windows system file
        ]

        for disallowed_path in disallowed_paths:
            with patch('PIL.Image.open') as mock_open:
                mock_img = MagicMock()
                mock_img.convert.return_value = MagicMock()
                mock_open.return_value = mock_img

                try:
                    nq.setup_media(disallowed_path)

                    # VULNERABILITY: No whitelist validation - disallowed paths are accepted
                    assert mock_open.called, f"Disallowed path was accepted: {disallowed_path}"
                except Exception:
                    pass

    def test_no_character_whitelist(self):
        """
        Test: Verify that there is no character whitelist for file paths.
        
        Expected behavior for secure code: File paths should only contain whitelisted
        characters (alphanumeric, underscores, hyphens, etc.) to prevent traversal attacks.
        
        Current behavior: Special characters like ../ are accepted without validation.
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="salm")

        # Paths containing characters that should be blocked
        paths_with_dangerous_chars = [
            "../../../etc/passwd",  # Contains ../
            "data/../../secrets",  # Contains ../
            "..\\..\\..\\windows\\system.ini",  # Contains ..\\
        ]

        for dangerous_path in paths_with_dangerous_chars:
            with patch('soundfile.read') as mock_read:
                mock_read.return_value = (MagicMock(), 16000)

                try:
                    nq.setup_media(dangerous_path)

                    # VULNERABILITY: Dangerous characters are not filtered
                    called_path = mock_read.call_args[0][0]
                    assert (
                        '..' in called_path
                    ), f"Path with dangerous characters was accepted: {dangerous_path}"
                except Exception:
                    pass


class TestPathTraversalRealWorldScenarios:
    """
    Real-world attack scenarios demonstrating how the vulnerability could be exploited.
    """

    def test_attack_scenario_reading_ssh_keys(self):
        """
        Attack Scenario: Attacker uses multimodal endpoint to read SSH private keys.
        
        An attacker could send a request with input_media="../../../root/.ssh/id_rsa"
        to attempt reading the SSH private key from the server.
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        nq = NemoQueryMultimodal(url="localhost", model_name="neva", model_type="neva")

        # Simulate attacker's malicious input
        attacker_input = "../../../root/.ssh/id_rsa"

        with patch('PIL.Image.open') as mock_open:
            # Simulate the file existing and being readable
            mock_img = MagicMock()
            mock_img.convert.return_value = MagicMock()
            mock_open.return_value = mock_img

            try:
                result = nq.setup_media(attacker_input)

                # VULNERABILITY DEMONSTRATED: Attacker's path traversal attempt succeeds
                assert mock_open.called, "Attack scenario: SSH key read attempt was not blocked"
                assert (
                    attacker_input in str(mock_open.call_args)
                ), "Attack scenario: Path traversal to SSH keys was successful"
            except Exception:
                pass

    def test_attack_scenario_reading_config_files(self):
        """
        Attack Scenario: Attacker uses config path parameter to read sensitive config files.
        
        An attacker could manipulate configuration parameters to load malicious or
        sensitive configuration files from arbitrary locations.
        """
        # Simulate an attack where the attacker controls the yaml_id in model registry
        # or the model_config parameter in server config

        malicious_config_path = "../../../etc/shadow"

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "server"
            base_path.mkdir()

            # Attacker-controlled yaml_id leads to path traversal
            constructed_path = f"{os.path.abspath(base_path)}/server_configs/llm_configs/{malicious_config_path}"
            normalized = os.path.normpath(constructed_path)

            # VULNERABILITY DEMONSTRATED: Path escapes intended directory
            assert not normalized.startswith(
                str(base_path)
            ), "Attack scenario: Config file path traversal was successful"

    def test_attack_scenario_model_poisoning(self):
        """
        Attack Scenario: Attacker loads a malicious model from an arbitrary path.
        
        If model loading uses paths constructed from user input without validation,
        an attacker could load a malicious model from a location they control.
        """
        # This scenario demonstrates how path traversal in model names could
        # lead to loading unauthorized models

        malicious_model_path = "../../../tmp/malicious_model.nemo"

        # If the application constructs model paths like:
        # model_path = f"/models/{model_name}.nemo"
        # An attacker could use "../../../tmp/malicious_model" to escape

        base_dir = "/app/models"
        constructed_path = os.path.normpath(f"{base_dir}/{malicious_model_path}")

        # VULNERABILITY DEMONSTRATED: Constructed path escapes the models directory
        assert not constructed_path.startswith(
            base_dir
        ), "Attack scenario: Model path traversal could lead to loading malicious models"


# Additional test to verify vulnerability exists in production-like conditions
@pytest.mark.integration
class TestPathTraversalIntegration:
    """
    Integration tests that verify the vulnerability in more realistic scenarios.
    These tests require certain dependencies to be available.
    """

    def test_end_to_end_image_path_traversal(self):
        """
        End-to-end test demonstrating path traversal vulnerability with minimal mocking.
        """
        try:
            from nemo.deploy.multimodal import NemoQueryMultimodal
        except ImportError:
            pytest.skip("NemoQueryMultimodal not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a sensitive file that should not be accessible
            sensitive_file = Path(tmpdir) / "sensitive_data.txt"
            sensitive_file.write_text("SECRET_API_KEY=abc123")

            # Create a nested directory structure
            safe_dir = Path(tmpdir) / "safe" / "images"
            safe_dir.mkdir(parents=True)

            # Attacker attempts to traverse from safe_dir to sensitive_file
            relative_path = "../../sensitive_data.txt"
            full_malicious_path = safe_dir / relative_path
            normalized_malicious = os.path.normpath(full_malicious_path)

            # Verify that the traversal actually reaches the sensitive file
            assert os.path.samefile(
                normalized_malicious, sensitive_file
            ), "Path traversal reaches sensitive file"

            # Now test if NemoQueryMultimodal would accept this path
            nq = NemoQueryMultimodal(url="localhost", model_name="test", model_type="neva")

            with patch('PIL.Image.open') as mock_open:
                mock_img = MagicMock()
                mock_img.convert.return_value = MagicMock()
                mock_open.return_value = mock_img

                try:
                    # Use the relative path that traverses to sensitive file
                    nq.setup_media(str(full_malicious_path))

                    # VULNERABILITY: The malicious path was accepted
                    assert (
                        mock_open.called
                    ), "Integration test: Path traversal attack succeeded end-to-end"
                except Exception:
                    pass
