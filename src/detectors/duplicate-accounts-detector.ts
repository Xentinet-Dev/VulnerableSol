import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects duplicate mutable accounts vulnerabilities
 * Enhanced version that detects multiple patterns
 */
export class DuplicateAccountsDetector extends BaseDetector {
  name = "Duplicate Mutable Accounts";
  description = "Detects when the same account appears multiple times in a context without validation";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Anchor struct with multiple mutable accounts
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("#[derive(Accounts)]")) {
        // Find the struct definition
        let structStart = -1;
        for (let j = i; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes("pub struct")) {
            structStart = j;
            break;
          }
        }

        if (structStart === -1) continue;

        // Extract all mutable accounts
        const mutableAccounts: string[] = [];
        const structBody = lines.slice(structStart, Math.min(structStart + 50, lines.length)).join("\n");
        
        // Find all mutable accounts
        const accountPattern = /#\[account\s*\(\s*mut[^)]*\)\]\s*pub\s+(\w+):/g;
        let match;
        while ((match = accountPattern.exec(structBody)) !== null) {
          mutableAccounts.push(match[1]);
        }

        // Check if struct has validation
        const hasValidation = structBody.includes('constraint') && 
                             (structBody.includes('!=') || structBody.includes('key() != key()'));

        if (mutableAccounts.length >= 2 && !hasValidation) {
          const structName = lines[structStart].match(/pub struct\s+(\w+)/)?.[1] || 'unknown';
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "duplicate-mutable-accounts");
          vulnerabilities.push({
            id: generateVulnerabilityId("duplicate-accounts", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Missing Duplicate Account Validation",
            description: pattern?.description || 
              `Struct ${structName} has ${mutableAccounts.length} mutable accounts without duplicate check`,
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1,
              contract: structName
            },
            recommendation: pattern?.codeExamples.patched || 
              `Add constraint: constraint = ${mutableAccounts[0]}.key() != ${mutableAccounts[1]}.key()`,
            codeSnippet: lines.slice(Math.max(0, i - 2), structStart + 20).join("\n"),
            metadata: {
              vulnerabilityType: 'duplicate-accounts',
              mutableAccounts: mutableAccounts
            },
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Manual account processing without deduplication
      if (line.includes("next_account_info")) {
        // Look for multiple next_account_info calls
        let accountCount = 0;
        const accountNames: string[] = [];
        
        for (let j = i; j < Math.min(i + 20, lines.length); j++) {
          if (lines[j].includes("next_account_info")) {
            accountCount++;
            const nameMatch = lines[j].match(/let\s+(\w+)\s*=\s*next_account_info/);
            if (nameMatch) {
              accountNames.push(nameMatch[1]);
            }
          }
          if (lines[j].includes("}") && lines[j].trim() === "}") {
            break;
          }
        }

        if (accountCount >= 2) {
          // Check if there's a comparison
          const afterCode = lines.slice(i, Math.min(i + 50, lines.length)).join("\n");
          const hasCheck = accountNames.some(acc => 
            afterCode.includes(`${acc}.key !=`) ||
            afterCode.includes(`${acc} !=`) ||
            afterCode.includes('check_duplicate') ||
            afterCode.includes('require!') && afterCode.includes('key() !=')
          );

          if (!hasCheck) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "duplicate-mutable-accounts");
            vulnerabilities.push({
              id: generateVulnerabilityId("duplicate-check-missing", context?.filePath, i + 1, vulnerabilities.length),
              title: "No Duplicate Account Check",
              description: "Processing multiple accounts without checking for duplicates",
              severity: Severity.HIGH,
              category: VulnerabilityCategory.ACCESS_CONTROL,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: `Add check: require!(${accountNames[0]}.key != ${accountNames[1]}.key, "Duplicate accounts")`,
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 10).join("\n"),
              references: pattern?.references
            });
          }
        }
      }
    }

    return vulnerabilities;
  }
}
