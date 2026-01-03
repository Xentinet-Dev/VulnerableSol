import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects initialization attack vulnerabilities
 * Identifies when initialize functions can be called multiple times
 */
export class InitializationAttackDetector extends BaseDetector {
  name = "Initialization Attack";
  description = "Detects when initialization functions can be called multiple times or without proper checks";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Initialize without checking if already initialized
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("fn initialize") || line.includes("pub fn initialize")) {
        // Find function body
        let functionBody = "";
        let braceCount = 0;
        let foundOpen = false;
        
        for (let j = i; j < Math.min(i + 100, lines.length); j++) {
          const currentLine = lines[j];
          braceCount += (currentLine.match(/\{/g) || []).length;
          braceCount -= (currentLine.match(/\}/g) || []).length;
          
          if (currentLine.includes('{')) foundOpen = true;
          functionBody += currentLine + "\n";
          
          if (foundOpen && braceCount === 0) break;
        }
        
        const hasInitCheck = functionBody.includes('is_initialized') ||
                            functionBody.includes('initialized') ||
                            (functionBody.includes('require!') && functionBody.includes('!')) ||
                            functionBody.includes('already_initialized') ||
                            functionBody.includes('discriminator');

        if (!hasInitCheck) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "initialization-attack");
          vulnerabilities.push({
            id: generateVulnerabilityId("init-no-check", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Initialize Without Initialization Check",
            description: pattern?.description || 
              "Initialize function can be called multiple times",
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: "initialize"
            },
            recommendation: pattern?.codeExamples.patched || 
              "Add: require!(!state.is_initialized, ErrorCode::AlreadyInitialized)",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 15).join("\n"),
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Anchor init without init constraint
      if (line.includes("#[derive(Accounts)]")) {
        // Find the struct
        let structBody = "";
        for (let j = i; j < Math.min(i + 30, lines.length); j++) {
          structBody += lines[j] + "\n";
          if (lines[j].includes("pub struct") && j > i) {
            // Found struct, check if it's Initialize
            if (lines[j].includes("Initialize")) {
              // Check for init constraint
              const hasInitConstraint = structBody.includes('#[account(init') ||
                                       structBody.includes('#[account(zero') ||
                                       structBody.includes('#[account(init,') ||
                                       structBody.includes('#[account(zero,');

              if (!hasInitConstraint && structBody.includes('#[account(mut')) {
                const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "initialization-attack");
                vulnerabilities.push({
                  id: generateVulnerabilityId("anchor-init-missing", context?.filePath, i + 1, vulnerabilities.length),
                  title: "Mutable Account Without Init Constraint",
                  description: "Account marked mutable but not initialized properly",
                  severity: Severity.HIGH,
                  category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
                  location: {
                    file: context?.filePath,
                    line: i + 1
                  },
                  recommendation: "Use #[account(init)] or #[account(zero)] for new accounts",
                  codeSnippet: lines.slice(Math.max(0, i - 2), i + 20).join("\n"),
                  references: pattern?.references
                });
              }
            }
            break;
          }
        }
      }

      // Pattern 3: Setting discriminator without checking
      if (line.includes("discriminator") && line.includes("=")) {
        const afterCode = lines.slice(i, Math.min(i + 10, lines.length)).join("\n");
        const hasCheck = afterCode.includes('if') && afterCode.includes('discriminator') ||
                        afterCode.includes('require!') && afterCode.includes('discriminator');

        if (!hasCheck) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "initialization-attack");
          vulnerabilities.push({
            id: generateVulnerabilityId("discriminator-overwrite", context?.filePath, i + 1, vulnerabilities.length),
            title: "Discriminator Set Without Check",
            description: "Setting account discriminator without checking if already set",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Check discriminator before setting to prevent reinitialization",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}
