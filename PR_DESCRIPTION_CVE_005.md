# Security Tests: CVE-005 - Remote Code Execution via Unsafe YAML Loading

## Summary

This PR adds comprehensive security tests to verify and document the vulnerability described in CVE-005.

## Details

**CVE ID**: CVE-005  
**Title**: [CVE-005] Remote Code Execution via Unsafe YAML Loading  
**Severity**: CRITICAL  
**Jira Issue**: https://ml6team.atlassian.net/browse/DR-137

## Description

The application is vulnerable to RCE via unsafe YAML loading. The repository uses Hydra and omegaconf for configuration, which rely on YAML files. Using `yaml.load()` without `SafeLoader` can allow an attacker to execute arbitrary code by crafting a malicious configuration file. This is a critical risk given the complexity of configurations in ML frameworks.

Grep results show multiple instances of `yaml.load()`. While some instances correctly use `Loader=yaml.SafeLoader`, others do not specify a loader, making them insecure. For example:
- `nemo/collections/asr/parts/preprocessing/perturb.py:1213: params = yaml.load(f)`
- `scripts/nemo_legacy_import/asr_checkpoint_port.py:49: params = yaml.load(f)`

## Solution Design

- Review all instances of `yaml.load()` and `yaml.unsafe_load()`.
- Replace all instances of `yaml.load(stream)` with `yaml.safe_load(stream)` or `yaml.load(stream, Loader=yaml.SafeLoader)`.
- Establish a policy to use only `yaml.safe_load` for loading YAML files from untrusted or potentially untrusted sources.

## Acceptance Criteria

- All identified instances of unsafe YAML loading are replaced with `yaml.safe_load`.
- The codebase is free of `yaml.load()` calls that do not specify a `SafeLoader`.
- The application is no longer vulnerable to RCE through malicious YAML files.

## Tests Added

This PR includes comprehensive security tests in `tests/security/test_cve_005_yaml_rce.py`:

### Vulnerability Detection Tests
1. **test_yaml_load_without_loader_is_vulnerable**: Demonstrates that `yaml.load()` without a Loader parameter is vulnerable to RCE
2. **test_yaml_load_with_fullloader_is_partially_vulnerable**: Tests that FullLoader may still be vulnerable to some attacks
3. **test_detect_unsafe_yaml_load_in_codebase**: Scans the codebase for unsafe `yaml.load()` patterns
4. **test_verify_specific_cve_files**: Verifies the specific files mentioned in the CVE report
5. **test_rce_proof_of_concept**: Proof of concept demonstrating the critical severity of RCE

### Safe Alternative Tests (Negative Tests)
6. **test_yaml_safeloader_prevents_rce**: Verifies that `yaml.load()` with SafeLoader prevents RCE
7. **test_yaml_safe_load_prevents_rce**: Verifies that `yaml.safe_load()` prevents RCE
8. **test_compare_safe_vs_unsafe_yaml_loading**: Educational comparison showing differences

### Ruamel.yaml Tests
9. **test_ruamel_yaml_safe_mode**: Tests that `ruamel.yaml` with `typ='safe'` prevents code execution
10. **test_detect_ruamel_yaml_unsafe_usage**: Scans for unsafe ruamel.yaml usage patterns

## Testing Methodology

These tests follow a comprehensive security testing approach:

- **Positive Tests**: Verify the vulnerability exists and can be exploited
- **Negative Tests**: Verify safe alternatives prevent exploitation
- **Code Scanning Tests**: Detect vulnerable patterns in the codebase
- **Proof of Concept**: Demonstrate real-world exploit scenarios

## Important Notes

⚠️ **This PR adds TESTS ONLY** - it does NOT fix the vulnerability in the codebase.

The purpose of these tests is to:
1. Document the security vulnerability
2. Verify that the vulnerability exists
3. Provide test coverage for future security fixes
4. Demonstrate both vulnerable and safe patterns

## Files Changed

- `tests/security/__init__.py` - New security test module initialization (13 lines)
- `tests/security/test_cve_005_yaml_rce.py` - Comprehensive security tests for CVE-005 (593 lines)

**Total**: 606 insertions(+), 0 deletions(-)

## Related Issues

- **Jira**: https://ml6team.atlassian.net/browse/DR-137
- **CVE**: CVE-005

## Recommendations

After this PR is merged, a follow-up PR should be created to:
1. Fix all instances of unsafe `yaml.load()` usage
2. Replace them with `yaml.safe_load()` or `yaml.load(stream, Loader=yaml.SafeLoader)`
3. Update code review guidelines to prevent future unsafe YAML loading

---

**Security Impact**: These tests will help identify and prevent Remote Code Execution vulnerabilities in YAML configuration loading.

## How to Create This PR

The branch `cursor/generate-security-tests-for-cve-005-222a` has been pushed to the repository.

**Option 1 - Via Web Interface**:
Visit: https://github.com/NielsRogge/NeMo/compare/main...cursor/generate-security-tests-for-cve-005-222a?expand=1

Then copy this description into the PR body.

**Option 2 - Via CLI** (if you have proper permissions):
```bash
gh pr create --title "Security Tests: CVE-005 - Remote Code Execution via Unsafe YAML Loading" \
             --body "$(cat PR_DESCRIPTION_CVE_005.md)"
```
