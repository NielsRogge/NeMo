# Security Tests for NeMo

This directory contains security-focused test suites designed to detect and document security vulnerabilities in the NeMo framework.

## ⚠️ Important Notice

**These tests are designed to DETECT vulnerabilities, NOT to fix them.**

The purpose of these security tests is to:
1. Document the presence of security vulnerabilities
2. Demonstrate attack vectors and exploitation techniques  
3. Provide test coverage for security remediation efforts
4. Track security issues for compliance and audit purposes

## Test Suites

### CVE-008: Arbitrary File Write Vulnerability

**Severity:** CRITICAL  
**JIRA:** https://ml6team.atlassian.net/browse/DR-138

#### Description
The NeMo framework contains multiple instances where file write operations may be vulnerable to arbitrary file writes. If output file paths can be controlled by users or malicious configurations, attackers could:
- Overwrite critical system files
- Write malicious scripts (e.g., web shells) to web-accessible directories
- Inject malicious content into application configuration files
- Create backdoors in the system

#### Affected Code Patterns
- `open(path, 'w')` and `open(path, 'wb')` with user-controllable paths
- `Path.write_text()` with user-controllable paths
- File operations without proper path validation
- Directory traversal vulnerabilities using `../` sequences
- Absolute path manipulation to sensitive locations

#### Test Files
- **test_cve_008_arbitrary_file_write.py**: Core vulnerability tests
  - Directory traversal attacks
  - Absolute path manipulation
  - Symlink following vulnerabilities
  - Path validation bypass techniques
  - Recommended validation approaches (for remediation reference)

- **test_cve_008_integration.py**: Integration tests for real code paths
  - NeMo Forced Aligner manifest output vulnerability
  - Multimodal export engine file write vulnerability
  - HuggingFace I/O model card write vulnerability
  - Checkpoint saving vulnerabilities
  - Data processing output injection
  - Artifact registration and extraction vulnerabilities

#### Running the Tests

Run all CVE-008 tests:
```bash
pytest tests/security/test_cve_008_*.py -v
```

Run specific test classes:
```bash
pytest tests/security/test_cve_008_arbitrary_file_write.py::TestCVE008ArbitraryFileWrite -v
pytest tests/security/test_cve_008_integration.py::TestCVE008AlignmentToolVulnerability -v
```

Run with security markers (if configured):
```bash
pytest -m security tests/security/
```

#### Expected Behavior
These tests are **expected to pass**, which indicates that the **vulnerabilities are present**. When the vulnerabilities are fixed, some of these tests may need to be updated or removed.

## Remediation Guidance

The test files include documentation of recommended approaches for fixing these vulnerabilities:

1. **Path Validation**: Use `os.path.realpath()` to resolve paths and validate they stay within allowed directories
2. **Whitelisting**: Maintain a whitelist of allowed output directories and reject any paths outside them
3. **Path Sanitization**: Remove dangerous characters like `../`, `..\\`, and absolute path markers from user input
4. **Least Privilege**: Run the application with minimal file system permissions
5. **Input Validation**: Validate all configuration inputs and reject suspicious paths

See `TestCVE008RecommendedValidation` class in `test_cve_008_arbitrary_file_write.py` for implementation examples.

## Contributing

When adding new security tests:

1. Create a new test file named `test_cve_XXX_<vulnerability_name>.py`
2. Include comprehensive documentation in the test docstrings:
   - CVE/vulnerability identifier
   - Severity level
   - JIRA issue link
   - Detailed description
   - Affected code locations
   - Attack vectors
3. Mark tests appropriately (`@pytest.mark.unit`, `@pytest.mark.security`, etc.)
4. Include both detection tests (showing vulnerability exists) and remediation examples
5. Update this README with information about the new test suite

## Security Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Follow the responsible disclosure process documented in SECURITY.md
3. Contact the security team at the designated security email
4. Include:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested remediation (if known)

## References

- **OWASP Path Traversal**: https://owasp.org/www-community/attacks/Path_Traversal
- **CWE-22: Improper Limitation of a Pathname**: https://cwe.mitre.org/data/definitions/22.html
- **CWE-73: External Control of File Name or Path**: https://cwe.mitre.org/data/definitions/73.html

## License

Copyright (c) 2025, NVIDIA CORPORATION. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
