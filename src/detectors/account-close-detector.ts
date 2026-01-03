import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects account close/rent reclamation attack vulnerabilities
 * Enhanced version that detects multiple patterns of unsafe account closing
 */
export class AccountCloseDetector extends BaseDetector {
  name = "Account Close/Rent Reclamation Attack";
  description = "Detects unsafe account closing operations that could allow attackers to drain accounts";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Direct lamport manipulation without ownership check
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for lamport transfer patterns
      if (line.includes(".lamports.borrow_mut()") && 
          (line.includes("+=") || line.includes("="))) {
        
        // Check if there's a corresponding zero-out (account close)
        let hasClose = false;
        let destination = "";
        let source = "";
        
        // Extract destination account
        const destMatch = line.match(/\*\*?(\w+)\.lamports\.borrow_mut\(\)\s*\+=/);
        if (destMatch) {
          destination = destMatch[1];
        }

        // Look ahead for zero-out
        for (let j = i; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes(".lamports.borrow_mut()") && 
              lines[j].includes("= 0") || lines[j].includes("= 0;")) {
            hasClose = true;
            const sourceMatch = lines[j].match(/\*\*?(\w+)\.lamports\.borrow_mut\(\)/);
            if (sourceMatch) {
              source = sourceMatch[1];
            }
            break;
          }
        }

        if (hasClose && source) {
          // Check if there's an ownership check before this
          const beforeCode = lines.slice(Math.max(0, i - 30), i).join("\n");
          const hasOwnerCheck = beforeCode.includes(`${source}.owner`) || 
                               beforeCode.includes('check_owner') ||
                               beforeCode.includes('assert_owned_by') ||
                               beforeCode.includes('require!') && beforeCode.includes('owner');

          if (!hasOwnerCheck) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "account-close-attack");
            vulnerabilities.push({
              id: generateVulnerabilityId("account-close", context?.filePath, i + 1, vulnerabilities.length),
              title: pattern?.name || "Unsafe Account Close - Missing Ownership Check",
              description: pattern?.description || 
                `Account ${source} is closed and lamports transferred to ${destination} without verifying ownership`,
              severity: Severity.CRITICAL,
              category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
              location: {
                file: context?.filePath,
                line: i + 1,
                function: this.extractFunctionName(content, i)
              },
              recommendation: pattern?.codeExamples.patched || 
                "Verify account ownership before closing: assert_owned_by(&source, &program_id)?",
              codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
              metadata: {
                vulnerabilityType: 'account-close',
                sourceAccount: source,
                destinationAccount: destination
              },
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 2: Close account in Anchor without proper constraints
      if (line.includes("#[account") && line.includes("close")) {
        // Extract the close target
        const closeMatch = line.match(/close\s*=\s*(\w+)/);
        
        if (closeMatch) {
          // Check if has_one or constraint for ownership
          const hasConstraint = line.includes('has_one') || 
                               line.includes('constraint') ||
                               line.includes('owner');
          
          // Also check surrounding lines
          let hasOwnershipConstraint = hasConstraint;
          for (let j = Math.max(0, i - 3); j < Math.min(i + 3, lines.length); j++) {
            if (lines[j].includes('constraint') && 
                (lines[j].includes('owner') || lines[j].includes('authority'))) {
              hasOwnershipConstraint = true;
              break;
            }
          }

          if (!hasOwnershipConstraint) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "account-close-attack");
            vulnerabilities.push({
              id: generateVulnerabilityId("anchor-close", context?.filePath, i + 1, vulnerabilities.length),
              title: "Anchor Account Close Without Ownership Constraint",
              description: "Account marked for closing without ownership verification constraint",
              severity: Severity.HIGH,
              category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Add constraint = <ownership check> to close attribute",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: Closing token accounts without checking balance
      if (line.includes("close_account") || 
          line.includes("CloseAccount") ||
          (line.includes("close") && line.includes("token"))) {
        
        const beforeCode = lines.slice(Math.max(0, i - 20), i).join("\n");
        const hasBalanceCheck = beforeCode.includes('.amount') || 
                               beforeCode.includes('balance') ||
                               beforeCode.includes('is_empty') ||
                               beforeCode.includes('amount == 0');

        if (!hasBalanceCheck) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "account-close-attack");
          vulnerabilities.push({
            id: generateVulnerabilityId("token-close", context?.filePath, i + 1, vulnerabilities.length),
            title: "Token Account Closed Without Balance Check",
            description: "Closing token account without verifying zero balance may lose tokens",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Check token account balance is 0 before closing",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 3).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }

  private extractFunctionName(code: string, lineIndex: number): string {
    const beforeMatch = code.substring(0, code.split("\n").slice(0, lineIndex + 1).join("\n").length);
    const fnMatch = beforeMatch.match(/(?:pub\s+)?fn\s+(\w+)/g);
    return fnMatch && fnMatch.length > 0 
      ? fnMatch[fnMatch.length - 1].match(/fn\s+(\w+)/)?.[1] || 'unknown'
      : 'unknown';
  }
}
