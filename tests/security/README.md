# Security Tests for NeMo

This directory contains security tests for various CVEs (Common Vulnerabilities and Exposures) identified in the NeMo codebase.

## Purpose

These tests are designed to:
1. **Verify** the presence of security vulnerabilities documented in CVE reports
2. **Demonstrate** how vulnerabilities can be exploited
3. **Document** safe alternatives and best practices
4. **Provide** regression testing to ensure vulnerabilities are fixed properly

## Important Note

⚠️ **These tests verify vulnerabilities exist; they do NOT fix them.**

The purpose of these tests is to:
- Document the security concerns for awareness
- Provide test coverage for future remediation efforts
- Demonstrate both vulnerable and safe code patterns
- Serve as regression tests after vulnerabilities are patched

## CVE-002: Command Injection

**File:** `test_cve_002_command_injection.py`

**Severity:** CRITICAL

**Jira Issue:** https://ml6team.atlassian.net/browse/DR-135

### Vulnerability Description

The NeMo codebase contains multiple instances of command injection vulnerabilities through:
- Unsafe use of `os.system()` with user-controllable input
- Use of `subprocess.run()` with `shell=True` and unsanitized arguments
- Use of `subprocess.check_output()` with `shell=True` and unsanitized arguments

### Vulnerable Files Identified

1. **nemo/utils/cloud.py** (line 115)
   - Uses `os.system()` with hardcoded command
   - Risk: MEDIUM (currently hardcoded but sets bad precedent)

2. **nemo/collections/llm/deploy/base.py** (line 36)
   - Uses `subprocess.run()` with `shell=True`
   - Command constructed from environment variables
   - Risk: HIGH

3. **scripts/dataset_processing/get_commonvoice_data.py** (line 175)
   - Uses `subprocess.run()` with `shell=True`
   - Command constructed from user-provided arguments (`args.language`)
   - Risk: CRITICAL

4. **scripts/tokenizers/get_hf_text_data.py** (line 81)
   - Uses `os.system()` with f-string containing config values
   - Risk: HIGH

5. **scripts/dataset_processing/tts/aishell3/get_data.py** (lines 102, 107)
   - Uses `subprocess.check_output()` and `subprocess.run()` with `shell=True`
   - Commands constructed from file paths
   - Risk: HIGH

### Test Coverage

The test suite includes:

#### 1. Vulnerability Detection Tests
- `test_detect_os_system_in_cloud_utils()` - Detects os.system() usage
- `test_detect_subprocess_shell_true_in_deploy_base()` - Detects subprocess with shell=True
- `test_detect_subprocess_shell_true_in_commonvoice_script()` - Detects vulnerable patterns in scripts
- `test_detect_os_system_in_hf_text_data_script()` - Detects f-string injection vulnerability
- `test_detect_subprocess_shell_true_in_aishell3_script()` - Detects multiple vulnerable patterns

#### 2. Exploitation Demonstration Tests
- `test_os_system_command_injection_vulnerability()` - Demonstrates os.system() exploitation
- `test_subprocess_shell_true_command_injection_vulnerability()` - Demonstrates subprocess exploitation
- `test_shell_metacharacter_exploitation()` - Shows various injection techniques (;, &&, ||, |, etc.)

#### 3. Safe Alternative Tests
- `test_safe_subprocess_without_shell()` - Shows safe subprocess usage without shell=True
- `test_safe_path_operations_instead_of_os_system()` - Demonstrates using pathlib instead of shell commands
- `test_safe_shlex_quote_usage()` - Shows how to use shlex.quote() for escaping
- `test_safe_input_validation_and_sanitization()` - Demonstrates input validation best practices

#### 4. Codebase Scanning Tests
- `test_scan_for_os_system_usage()` - Scans for all os.system() usage
- `test_scan_for_subprocess_shell_true_usage()` - Scans for subprocess with shell=True
- `test_verify_no_input_sanitization_in_vulnerable_code()` - Confirms lack of sanitization

#### 5. Risk Assessment Tests
- `test_assess_cloud_utils_risk()` - Documents risk in cloud utilities
- `test_assess_deploy_base_risk()` - Documents risk in deployment code
- `test_assess_data_processing_scripts_risk()` - Documents risk in data processing scripts

### Running the Tests

To run all security tests:
```bash
pytest tests/security/test_cve_002_command_injection.py -v
```

To run only security-marked tests:
```bash
pytest tests/security/test_cve_002_command_injection.py -v -m security
```

To run specific test classes:
```bash
pytest tests/security/test_cve_002_command_injection.py::TestCommandInjectionDetection -v
```

### Remediation Guidelines

To fix the command injection vulnerabilities:

1. **Replace os.system() with safer alternatives:**
   ```python
   # UNSAFE
   os.system(f"rm {filename}")
   
   # SAFE
   Path(filename).unlink()
   ```

2. **Use subprocess without shell=True:**
   ```python
   # UNSAFE
   subprocess.run(f"cat {filename}", shell=True)
   
   # SAFE
   subprocess.run(["cat", filename], shell=False)
   ```

3. **If shell=True is absolutely necessary, use shlex.quote():**
   ```python
   import shlex
   
   # SAFER (but still avoid if possible)
   subprocess.run(f"cat {shlex.quote(filename)}", shell=True)
   ```

4. **Validate and sanitize all user input:**
   ```python
   import re
   
   def is_safe_filename(filename):
       # Only allow alphanumeric, underscore, hyphen, dot
       return bool(re.match(r'^[a-zA-Z0-9._-]+$', filename))
   
   if not is_safe_filename(user_input):
       raise ValueError("Invalid filename")
   ```

### Attack Vectors

Common shell metacharacters used for command injection:
- `;` - Command separator
- `&&` - Conditional AND execution
- `||` - Conditional OR execution
- `|` - Pipe output to another command
- `` ` `` - Command substitution (backticks)
- `$()` - Command substitution
- `>` `>>` - Output redirection
- `<` - Input redirection
- `\n` - Newline (in some contexts)

### References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Python shlex documentation](https://docs.python.org/3/library/shlex.html)

## Contributing

When adding new security tests:

1. Follow the existing test structure and naming conventions
2. Include comprehensive documentation in docstrings
3. Use the `@pytest.mark.security` decorator
4. Demonstrate both vulnerable and safe patterns
5. Include risk assessments and remediation guidelines
6. Update this README with new CVE information

## License

Copyright (c) 2025, NVIDIA CORPORATION. All rights reserved.

Licensed under the Apache License, Version 2.0.
