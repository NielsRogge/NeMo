# CVE-005: Remote Code Execution via Unsafe YAML Loading - Security Tests

## Overview

This directory contains comprehensive security tests for **CVE-005**, a CRITICAL vulnerability related to unsafe YAML loading in the NeMo codebase.

**CVE ID**: CVE-005  
**Severity**: CRITICAL  
**Jira Issue**: https://ml6team.atlassian.net/browse/DR-137

## Vulnerability Description

The application is vulnerable to Remote Code Execution (RCE) through unsafe YAML loading. Using `yaml.load()` without `SafeLoader` allows attackers to execute arbitrary Python code by crafting malicious YAML configuration files.

### Affected Files

According to the CVE report, the following files contain unsafe YAML loading:

1. `nemo/collections/asr/parts/preprocessing/perturb.py:1213`
   ```python
   params = yaml.load(f)  # UNSAFE
   ```

2. `scripts/nemo_legacy_import/asr_checkpoint_port.py:49`
   ```python
   params = yaml.load(f)  # UNSAFE
   ```

## Test Files

### 1. `test_cve_005_yaml_loading.py`

Comprehensive unit tests covering:

- **TestUnsafeYAMLLoading**: Tests demonstrating the vulnerability
  - Unsafe `yaml.load()` without Loader parameter
  - Safe loading patterns that prevent exploitation
  - RCE payload variations and attack vectors
  - ruamel.yaml security configurations

- **TestCodebaseYAMLUsage**: Codebase analysis tests
  - Scanning for unsafe `yaml.load()` usage
  - Verification of no `yaml.unsafe_load()` usage
  - Documentation of YAML import patterns

- **TestYAMLConfigurationSecurity**: Configuration-specific tests
  - Malicious config file handling
  - Nested malicious object detection
  - YAML anchor and alias safety
  - Merge key security

- **TestYAMLSecurityBestPractices**: Best practices enforcement
  - PyYAML version checks
  - Safe alternative verification

### 2. `test_cve_005_codebase_scan.py`

Automated codebase scanning tests:

- **YAMLSecurityScanner**: Scanner class for detecting unsafe patterns
  - Pattern detection for `yaml.load()` without SafeLoader
  - Detection of `yaml.unsafe_load()`
  - Detection of `FullLoader` usage
  - Detection of ruamel.yaml without `typ='safe'`

- **TestCVE005CodebaseScan**: Comprehensive scanning tests
  - Scanning known vulnerable files
  - Export module scanning
  - Collections module scanning
  - Full codebase scanning
  - YAML import verification

- **TestCVE005SpecificLines**: Line-specific tests
  - Tests for exact lines mentioned in CVE report
  - Targeted verification of reported vulnerabilities

## Running the Tests

### Run all CVE-005 tests:
```bash
pytest tests/security/test_cve_005*.py -v
```

### Run specific test file:
```bash
pytest tests/security/test_cve_005_yaml_loading.py -v
```

### Run codebase scan only:
```bash
pytest tests/security/test_cve_005_codebase_scan.py -v
```

### Run with detailed output:
```bash
pytest tests/security/test_cve_005*.py -v -s
```

## Expected Test Results

⚠️ **IMPORTANT**: These tests are designed to **DETECT** the vulnerability, not fix it.

- **FAILING tests indicate the vulnerability EXISTS** in the codebase
- **PASSING tests indicate the vulnerability is MITIGATED**

The tests will fail with detailed reports showing:
- File paths with unsafe YAML usage
- Line numbers of vulnerable code
- Severity levels (CRITICAL/HIGH)
- Remediation suggestions

## Remediation

To fix CVE-005, replace all unsafe YAML loading patterns:

### ❌ Unsafe Patterns:
```python
# UNSAFE - allows arbitrary code execution
yaml.load(stream)
yaml.load(stream, Loader=yaml.Loader)
yaml.load(stream, Loader=yaml.FullLoader)
yaml.unsafe_load(stream)
```

### ✅ Safe Patterns:
```python
# SAFE - prevents code execution
yaml.safe_load(stream)
yaml.load(stream, Loader=yaml.SafeLoader)

# For ruamel.yaml
from ruamel.yaml import YAML
yaml = YAML(typ='safe')
yaml.load(stream)
```

## Attack Example

Here's how an attacker could exploit unsafe YAML loading:

```yaml
# malicious_config.yaml
# Appears to be a normal config file
model:
  name: bert-base
  # Hidden malicious payload
  !!python/object/apply:os.system
  args: ['rm -rf /important/data']
```

When loaded with unsafe `yaml.load()`, this executes `os.system('rm -rf /important/data')`.

## Security Impact

- **Severity**: CRITICAL
- **Attack Vector**: Configuration file injection
- **Impact**: Complete system compromise, data exfiltration, denial of service
- **Exploitability**: Easy - requires only ability to provide a config file

## References

- [PyYAML Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

## Test Maintenance

These tests should be:
1. Run in CI/CD pipeline before every merge
2. Updated when new YAML loading code is added
3. Extended when new attack vectors are discovered
4. Reviewed quarterly for coverage completeness

## Contact

For security concerns related to this CVE:
- Jira: https://ml6team.atlassian.net/browse/DR-137
- Security Team: [Contact details]

---

**Note**: This test suite is part of the security assessment process. The tests are intentionally designed to fail when vulnerabilities are present to ensure continuous security monitoring.
