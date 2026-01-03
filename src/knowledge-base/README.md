# Vulnerability Knowledge Base

This directory contains the comprehensive vulnerability registry that trains the scanner to detect known security issues.

## Structure

- `vulnerability-registry.ts`: Complete registry of all known vulnerabilities with:
  - Detection patterns
  - Code examples (vulnerable vs patched)
  - Severity levels
  - References to security research

## Vulnerability Categories

### Solana Program Vulnerabilities
- Missing Ownership Checks
- Missing Signer Checks
- Type Confusion / Arbitrary CPI
- Integer Overflow/Underflow
- Precision Loss
- Re-initialization Attack
- Crank/Permissionless Instruction Abuse
- Incorrect Account Data Matching
- PDA Abuse

### dApp/Frontend Vulnerabilities
- Supply Chain Attacks
- DNS Hijacking
- Cross-Site Scripting (XSS)
- Phishing / Social Engineering
- Wallet Integration Flaws

### Ecosystem Vulnerabilities
- Bridge Exploits
- Admin Key/Governance Compromise

### EVM Vulnerabilities
- Reentrancy
- Weak Oracle Implementation

## Adding New Vulnerabilities

To add a new vulnerability pattern:

1. Add it to the appropriate array in `vulnerability-registry.ts`
2. Create a detector in `../detectors/` if needed
3. Register the detector in the scanner initialization

Example:

```typescript
{
  id: "new-vulnerability",
  name: "New Vulnerability Name",
  category: VulnerabilityCategory.ACCESS_CONTROL,
  severity: Severity.HIGH,
  description: "Description of the vulnerability",
  detectionPatterns: [
    "pattern1",
    "pattern2"
  ],
  codeExamples: {
    vulnerable: "// Vulnerable code example",
    patched: "// Patched code example"
  },
  references: ["Reference URL or paper"]
}
```

## Training the Scanner

The vulnerability registry serves as training data for the scanner. Each detector uses the registry to:
- Understand what to look for
- Provide accurate descriptions
- Suggest proper fixes
- Reference security research

This ensures consistent, well-documented vulnerability detection across all scan types.

