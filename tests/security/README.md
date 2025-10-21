# Security Tests for NeMo Framework

This directory contains security-focused tests that verify and document security vulnerabilities in the NeMo framework.

## ⚠️ IMPORTANT NOTICE

**These tests document CRITICAL security vulnerabilities that currently exist in the codebase.**

The tests in this directory are designed to:
1. **Verify** the presence of known security vulnerabilities
2. **Document** attack vectors and exploitation techniques
3. **Provide** regression tests for when vulnerabilities are fixed
4. **Demonstrate** proper security validation requirements

## CVE-004: Path Traversal Vulnerability

**Severity:** CRITICAL  
**Jira Issue:** [DR-136](https://ml6team.atlassian.net/browse/DR-136)

### Vulnerability Description

The NeMo framework reads and processes files from disk, including datasets and models. If file paths can be influenced by user input (e.g., through a configuration file or an API endpoint), an attacker could craft a path to read sensitive files outside the intended directory. This is especially relevant for deployed models using the `nemo.deploy` module.

### Test Coverage

#### 1. `test_cve_004_path_traversal.py`
Tests for path traversal vulnerabilities in core file loading functionality:
- Model checkpoint loading (`ModelPT.restore_from`)
- Deploy module checkpoint paths (`DeployBase`)
- Megatron LLM deployable checkpoint loading
- Checkpoint version detection path handling
- File path validation and sanitization
- Directory traversal attack vectors
- Various encoding and bypass techniques

#### 2. `test_cve_004_config_file_vulnerabilities.py`
Tests for path traversal through configuration files:
- YAML configuration file path handling
- Model checkpoint paths in configs
- Dataset paths in configs
- Artifact paths in configs
- Configuration interpolation attacks
- Nested configuration path traversal
- Config merging and override attacks

#### 3. `test_cve_004_deployment_api_vulnerabilities.py`
Tests for path traversal in deployment APIs and services:
- REST API model loading endpoints
- FastAPI interface path handling
- PyTriton deployment path validation
- Model query endpoints with file access
- Multimodal deployment path handling
- Error message information disclosure
- Container configuration attacks

## Attack Vectors Tested

The tests cover various attack techniques including:

### Basic Path Traversal
- `../../../etc/passwd` - Standard directory traversal
- `../../sensitive/file.txt` - Relative path escape
- `/etc/passwd` - Absolute path access

### Encoding Attacks
- `%2e%2e%2f` - URL-encoded traversal
- `%252e%252e%252f` - Double URL-encoded traversal
- Unicode variations (`\u002e`, `\uff0e`)

### Platform-Specific
- `..\\..\\` - Windows-style backslash traversal
- Mixed separators (`../..\\`)

### Advanced Techniques
- Null byte injection (`../../etc/passwd\x00.nemo`)
- Symlink traversal
- Configuration interpolation (`${base}/../../../etc/passwd`)

## Affected Components

The following components have been identified as vulnerable:

1. **nemo.deploy.deploy_base.DeployBase**
   - `__init__(checkpoint_path=...)` accepts unsanitized paths
   - `_init_nemo_model()` uses checkpoint paths without validation

2. **nemo.core.classes.ModelPT**
   - `restore_from(restore_path=...)` accepts unsanitized paths

3. **nemo.deploy.nlp.megatronllm_deployable.MegatronLLMDeploy**
   - `get_deployable(nemo_checkpoint_filepath=...)` accepts unsanitized paths

4. **nemo.deploy.utils.nemo_checkpoint_version**
   - Processes paths without validation

5. **Configuration Handling**
   - OmegaConf configurations with path fields
   - YAML/JSON configs with model/dataset paths

6. **API Endpoints**
   - REST API model loading endpoints
   - FastAPI path parameters
   - PyTriton deployment configurations

## Security Requirements

To remediate these vulnerabilities, the following security controls must be implemented:

### 1. Path Validation
```python
def validate_path(user_path: str, allowed_base: str) -> Path:
    """Validate that user_path is within allowed_base directory."""
    # Resolve to absolute path
    abs_path = Path(user_path).resolve()
    allowed_abs = Path(allowed_base).resolve()
    
    # Check if within allowed directory
    if not str(abs_path).startswith(str(allowed_abs)):
        raise SecurityError(f"Path {user_path} is outside allowed directory")
    
    return abs_path
```

### 2. Character Whitelisting
- Define allowed characters for file paths
- Reject paths with suspicious characters (null bytes, control characters)
- Validate path components individually

### 3. Symlink Validation
- Resolve all symlinks
- Validate symlink targets are within allowed directories
- Consider disabling symlink following in sensitive contexts

### 4. Configuration Validation
- Validate all path fields in configurations
- Apply validation to interpolated values
- Validate paths from environment variables

### 5. API Input Validation
- Validate all path inputs from API requests
- Sanitize before logging or error messages
- Rate limit invalid path attempts
- Return generic error messages

## Running the Tests

To run all security tests:
```bash
pytest tests/security/ -v
```

To run tests for a specific CVE:
```bash
pytest tests/security/test_cve_004_*.py -v
```

## Expected Behavior

**Currently:** Most tests should PASS, indicating the vulnerabilities exist.

**After remediation:** Tests should be updated to verify that:
1. Invalid paths are rejected with appropriate errors
2. Validation functions properly sanitize inputs
3. Security controls cannot be bypassed

## Contributing

When adding new security tests:

1. **Document the vulnerability clearly** in the test docstring
2. **Explain the attack vector** and potential impact
3. **Provide specific examples** of malicious inputs
4. **Reference related CVEs or issues**
5. **Include remediation requirements**

## References

- **CVE ID:** CVE-004
- **Jira Issue:** [DR-136](https://ml6team.atlassian.net/browse/DR-136)
- **OWASP:** [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory

## Disclaimer

These tests are for security research and vulnerability documentation purposes. They should only be run in controlled environments. Do not use these techniques against systems you do not own or have explicit permission to test.
