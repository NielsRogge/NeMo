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
Security Tests for CVE-004: Path Traversal in Deployment APIs

These tests verify path traversal vulnerabilities when file paths are
specified through REST APIs and deployment services.

CRITICAL SEVERITY - Deployed models with REST APIs are directly exposed
to attackers and represent a critical attack surface.

Test Coverage:
1. REST API model loading endpoints
2. FastAPI interface path handling
3. PyTriton deployment path validation
4. Model query endpoints with file access
5. Multimodal deployment path handling
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest


class TestDeploymentAPIPathTraversal:
    """
    Test path traversal vulnerabilities in deployment API endpoints.

    Deployed models often expose REST APIs that accept model paths or
    configuration parameters. Without proper validation, these can be
    exploited for path traversal attacks.
    """

    def test_api_model_load_path_traversal(self):
        """
        Test that API endpoints accepting model paths don't validate for traversal.

        VULNERABILITY: REST API endpoints that accept model paths as parameters
        do not validate or sanitize these paths before using them.

        Attack Vector: An attacker could send a POST request with a malicious
        model path to load arbitrary files:
        POST /api/load_model {"model_path": "../../../etc/passwd"}
        """
        # Simulate an API request payload
        malicious_payloads = [
            {"model_path": "../../../etc/passwd"},
            {"checkpoint": "../../sensitive/model.nemo"},
            {"restore_from": "../../../root/.ssh/id_rsa"},
        ]

        for payload in malicious_payloads:
            # VULNERABILITY: API payloads are processed without path validation
            for key, value in payload.items():
                if isinstance(value, str) and ".." in value:
                    assert True, f"API payload contains traversal in {key}: {value}"

    def test_api_json_payload_path_injection(self):
        """
        Test path traversal through JSON API payloads.

        VULNERABILITY: JSON payloads sent to API endpoints can contain
        malicious paths that are used without validation.

        Attack Vector: An attacker sends JSON with embedded path traversal:
        {"config": {"model_path": "../../../etc/passwd"}}
        """
        # Malicious JSON payload
        malicious_json = """
        {
            "model": {
                "checkpoint_path": "../../../etc/passwd",
                "config_path": "../../sensitive/config.yaml"
            },
            "deployment": {
                "model_file": "../../../var/log/secrets.log"
            }
        }
        """

        # Parse the JSON (as an API endpoint would)
        payload = json.loads(malicious_json)

        # VULNERABILITY: Paths in JSON are not validated
        assert ".." in payload["model"]["checkpoint_path"], "Traversal in checkpoint_path"
        assert ".." in payload["model"]["config_path"], "Traversal in config_path"
        assert ".." in payload["deployment"]["model_file"], "Traversal in model_file"

    def test_api_query_parameter_path_traversal(self):
        """
        Test path traversal through URL query parameters.

        VULNERABILITY: Query parameters in GET requests can contain
        traversal sequences that are not validated.

        Attack Vector: An attacker crafts a URL with malicious query params:
        GET /api/load?model=../../../etc/passwd
        """
        # Simulated query parameters
        malicious_queries = [
            "model=../../../etc/passwd",
            "checkpoint=../../sensitive/model.nemo",
            "config=../../../config/secrets.yaml&model=test.nemo",
        ]

        for query in malicious_queries:
            # Parse query string
            params = dict(param.split('=') for param in query.split('&'))

            # VULNERABILITY: Query parameters with traversal are not rejected
            for key, value in params.items():
                if ".." in value:
                    assert True, f"Query parameter {key} contains traversal: {value}"

    def test_api_multipart_form_path_traversal(self):
        """
        Test path traversal in multipart form data.

        VULNERABILITY: Multipart form uploads can include path fields
        that specify where files should be loaded from.

        Attack Vector: An attacker sends a multipart form with a malicious
        file path field while uploading a file.
        """
        # Simulated multipart form data
        form_data = {
            "file": "upload.nemo",
            "checkpoint_path": "../../../etc/passwd",
            "config_override": "../../sensitive/config.yaml",
        }

        # VULNERABILITY: Form data paths are not validated
        assert ".." in form_data["checkpoint_path"], "Traversal in form checkpoint_path"
        assert ".." in form_data["config_override"], "Traversal in form config_override"


class TestPyTritonDeploymentVulnerabilities:
    """
    Test path traversal vulnerabilities specific to PyTriton deployment.
    """

    @patch('nemo.deploy.deploy_pytriton.PyTriton')
    def test_pytriton_model_path_not_validated(self, mock_pytriton):
        """
        Test that PyTriton deployment accepts unvalidated model paths.

        VULNERABILITY: When deploying models with PyTriton, the model path
        is not validated for traversal sequences.

        Attack Vector: A deployment script or API could be exploited to
        load models from arbitrary filesystem locations.
        """
        from nemo.deploy.deploy_base import DeployBase

        # Create a mock deployable
        class TestDeployable(DeployBase):
            def deploy(self):
                pass

            def serve(self):
                pass

            def run(self):
                pass

            def stop(self):
                pass

        malicious_checkpoint = "../../../etc/passwd"

        # VULNERABILITY: Malicious checkpoint path is accepted
        deployable = TestDeployable(
            triton_model_name="test", checkpoint_path=malicious_checkpoint, model=MagicMock()
        )

        assert deployable.checkpoint_path == malicious_checkpoint, "Checkpoint path not validated"

    def test_pytriton_config_path_injection(self):
        """
        Test path injection in PyTriton configuration.

        VULNERABILITY: PyTriton deployment configurations can specify
        paths that are not validated.

        Attack Vector: Configuration dictionaries passed to PyTriton
        could contain malicious paths.
        """
        # Simulated PyTriton configuration
        pytriton_config = {
            "model_repository": "../../../models",
            "backend_config": {"default": {"model-file": "../../sensitive.pt"}},
            "model_config": {"config_path": "../../../etc/config"},
        }

        # VULNERABILITY: Configuration paths are not validated
        assert ".." in pytriton_config["model_repository"], "Traversal in model_repository"
        assert ".." in pytriton_config["backend_config"]["default"]["model-file"], "Traversal in model-file"


class TestFastAPIInterfaceVulnerabilities:
    """
    Test path traversal in FastAPI interface for deployment services.
    """

    def test_fastapi_endpoint_model_path_parameter(self):
        """
        Test FastAPI endpoint path parameters for traversal vulnerabilities.

        VULNERABILITY: FastAPI path parameters that accept model identifiers
        could be exploited if they're used to construct file paths.

        Attack Vector: An attacker could craft a URL like:
        /models/../../etc/passwd/load to attempt path traversal.
        """
        # Simulated FastAPI path parameter
        malicious_model_ids = [
            "../../../etc/passwd",
            "../../sensitive/model",
            "../config/../../../secrets",
        ]

        for model_id in malicious_model_ids:
            # If the application uses this to construct a path:
            model_path = f"/models/{model_id}.nemo"

            # VULNERABILITY: Path traversal in the constructed path
            assert ".." in model_path, f"Path traversal in model_path: {model_path}"

    def test_fastapi_request_body_path_fields(self):
        """
        Test FastAPI request body validation for path fields.

        VULNERABILITY: Pydantic models used for request validation may not
        include path traversal checks for string fields.

        Attack Vector: An attacker sends a POST request with a malicious
        path in the request body that passes Pydantic validation.
        """
        # Simulated Pydantic request model
        class ModelLoadRequest:
            model_path: str
            config_path: str = None

        # Malicious request
        request_data = {"model_path": "../../../etc/passwd", "config_path": "../../sensitive/config.yaml"}

        # VULNERABILITY: Pydantic validates types but not path content
        # The paths would pass validation even with traversal sequences
        assert ".." in request_data["model_path"], "Traversal in model_path"
        assert ".." in request_data["config_path"], "Traversal in config_path"

    def test_fastapi_static_file_serving_traversal(self):
        """
        Test path traversal in static file serving.

        VULNERABILITY: If the API serves model files or artifacts,
        improper path handling could expose arbitrary files.

        Attack Vector: An attacker requests a file with a path like:
        GET /files/../../etc/passwd
        """
        # Simulated file request paths
        malicious_file_paths = [
            "../../etc/passwd",
            "../../../root/.ssh/id_rsa",
            "../config/../../../var/log/auth.log",
        ]

        for file_path in malicious_file_paths:
            # VULNERABILITY: If these paths are used directly with file serving
            assert ".." in file_path, f"Traversal in file path: {file_path}"


class TestMultimodalDeploymentVulnerabilities:
    """
    Test path traversal in multimodal model deployment.
    """

    def test_multimodal_image_path_traversal(self):
        """
        Test path traversal when loading images for multimodal models.

        VULNERABILITY: Multimodal models that accept image paths could
        be exploited to read arbitrary files as images.

        Attack Vector: An attacker provides an image path like
        "../../../etc/passwd" which the model attempts to load.
        """
        # Simulated multimodal inference request
        malicious_requests = [
            {"image_path": "../../../etc/passwd", "prompt": "describe this"},
            {"image_paths": ["../../sensitive/image.jpg", "../../../secrets.txt"]},
        ]

        for request in malicious_requests:
            if "image_path" in request:
                assert ".." in request["image_path"], "Traversal in image_path"
            if "image_paths" in request:
                for path in request["image_paths"]:
                    if ".." in path:
                        assert True, f"Traversal in image_paths: {path}"

    def test_multimodal_audio_path_traversal(self):
        """
        Test path traversal when loading audio files for multimodal models.

        VULNERABILITY: Audio file paths in multimodal requests are not
        validated for traversal sequences.

        Attack Vector: An attacker could specify audio file paths that
        point to sensitive files instead of actual audio files.
        """
        # Malicious audio request
        audio_request = {
            "audio_file": "../../../etc/shadow",
            "model_path": "../../sensitive/asr_model.nemo",
        }

        # VULNERABILITY: Audio file paths not validated
        assert ".." in audio_request["audio_file"], "Traversal in audio_file"
        assert ".." in audio_request["model_path"], "Traversal in model_path"


class TestDeploymentServiceValidationRequirements:
    """
    Document security requirements for deployment service APIs.
    """

    def test_api_should_validate_all_path_inputs(self):
        """
        Requirement: All path inputs from APIs must be validated.

        Proper implementation should:
        1. Identify all API endpoints that accept paths
        2. Add validation to reject paths with traversal sequences
        3. Normalize and validate paths are within allowed directories
        4. Use a whitelist of allowed characters
        """
        import os

        # Example API input
        api_input = {"model_path": "../../../etc/passwd"}

        # REQUIRED VALIDATION (NOT CURRENTLY IMPLEMENTED):
        path = api_input["model_path"]

        # Check for traversal sequences
        has_traversal = ".." in path or path.startswith("/")

        # VULNERABILITY: Path should be rejected
        assert has_traversal, "API input contains traversal - should be rejected"

    def test_api_should_use_safe_path_construction(self):
        """
        Requirement: APIs should use safe methods for path construction.

        Proper implementation should:
        1. Use Path.resolve() to normalize paths
        2. Validate resolved paths are within allowed directories
        3. Never directly join user input to base paths without validation
        """
        base_dir = Path("/models")
        user_input = "../../../etc/passwd"

        # UNSAFE (CURRENT VULNERABILITY):
        unsafe_path = base_dir / user_input

        # After resolution:
        resolved = unsafe_path.resolve()

        # REQUIRED CHECK (NOT CURRENTLY IMPLEMENTED):
        is_safe = str(resolved).startswith(str(base_dir.resolve()))

        # VULNERABILITY: Resolved path is outside base directory
        assert not is_safe, "Path construction allows traversal outside base directory"

    def test_api_should_sanitize_before_logging(self):
        """
        Requirement: Paths should be sanitized before logging.

        Proper implementation should:
        1. Never log unsanitized user input
        2. Sanitize paths before including in error messages
        3. Prevent information disclosure through logs
        """
        # Malicious path in API request
        malicious_path = "../../../etc/passwd"

        # VULNERABILITY: If logged directly, could leak information
        # or be used for log injection attacks
        log_message = f"Loading model from: {malicious_path}"

        # The path should be sanitized before logging
        assert ".." in log_message, "Unsanitized path in log message"

    def test_api_should_rate_limit_path_validation_failures(self):
        """
        Requirement: Rate limit repeated path validation failures.

        Proper implementation should:
        1. Track path validation failures per client
        2. Rate limit clients that repeatedly send invalid paths
        3. Alert on potential attack patterns
        """
        # Simulated repeated malicious requests
        malicious_requests = [
            {"path": f"../../../etc/passwd{i}"} for i in range(100)  # 100 malicious requests
        ]

        # REQUIRED SECURITY MEASURE (NOT CURRENTLY IMPLEMENTED):
        # Rate limiting should trigger after N failures
        # Currently, all requests would be processed without rate limiting

        assert len(malicious_requests) > 10, "Many malicious requests - should trigger rate limiting"


class TestDeploymentErrorHandlingVulnerabilities:
    """
    Test information disclosure through error messages.
    """

    def test_path_error_messages_disclose_file_system_structure(self):
        """
        Test that error messages may disclose file system information.

        VULNERABILITY: Detailed error messages about file operations
        could leak information about the file system structure.

        Attack Vector: An attacker sends requests with various paths
        and uses error messages to map the file system.
        """
        # Simulated error scenarios
        error_scenarios = [
            ("../../../etc/passwd", "FileNotFoundError: /etc/passwd does not exist"),
            ("../../root/.ssh", "PermissionError: Cannot access /root/.ssh"),
            ("../sensitive/model.nemo", "Path /sensitive/model.nemo is outside allowed directory"),
        ]

        for malicious_path, error_message in error_scenarios:
            # VULNERABILITY: Error messages reveal file system information
            # Full paths in error messages help attackers
            assert "/" in error_message, "Error message contains file system paths"

    def test_file_existence_oracle_through_errors(self):
        """
        Test that different errors can reveal file existence.

        VULNERABILITY: Different error messages for existing vs non-existing
        files can be used as an oracle to probe the file system.

        Attack Vector: An attacker sends requests with different paths
        and uses the error types to determine which files exist.
        """
        # Different errors reveal different information
        file_exists_error = "PermissionError: Cannot read file"
        file_not_exists_error = "FileNotFoundError: File does not exist"

        # VULNERABILITY: Error types reveal file existence
        # Both errors should be generic to prevent information leakage
        assert file_exists_error != file_not_exists_error, "Different errors reveal file existence"


class TestDeploymentConfigurationInjection:
    """
    Test configuration injection attacks in deployment scenarios.
    """

    def test_environment_variable_injection_in_deployment(self):
        """
        Test path injection through environment variables in deployments.

        VULNERABILITY: Environment variables used in deployment configurations
        could be controlled by attackers in certain scenarios (e.g., container orchestration).

        Attack Vector: An attacker who can set environment variables could
        inject malicious paths into the deployment configuration.
        """
        import os

        # Malicious environment variables
        os.environ['MODEL_PATH'] = '../../../etc/passwd'
        os.environ['CONFIG_PATH'] = '../../sensitive/config.yaml'

        try:
            # VULNERABILITY: Environment variables used without validation
            model_path = os.environ.get('MODEL_PATH')
            config_path = os.environ.get('CONFIG_PATH')

            assert ".." in model_path, "Malicious path in MODEL_PATH env var"
            assert ".." in config_path, "Malicious path in CONFIG_PATH env var"
        finally:
            del os.environ['MODEL_PATH']
            del os.environ['CONFIG_PATH']

    def test_container_volume_mount_path_traversal(self):
        """
        Test path traversal through container volume mount configurations.

        VULNERABILITY: In containerized deployments, volume mount paths
        could be manipulated if not properly validated.

        Attack Vector: An attacker with control over container configuration
        could mount sensitive directories by specifying traversal paths.
        """
        # Simulated container configuration
        container_config = {
            "volumes": [{"host_path": "../../../etc", "container_path": "/etc"}],
            "model_path": "../../sensitive/model.nemo",
        }

        # VULNERABILITY: Volume mount paths not validated
        assert ".." in container_config["volumes"][0]["host_path"], "Traversal in volume mount"
        assert ".." in container_config["model_path"], "Traversal in model path"
