import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects upgrade authority vulnerabilities
 * Identifies when programs can be upgraded without proper safeguards
 */
export class UpgradeAuthorityDetector extends BaseDetector {
  name = "Upgrade Authority Attack";
  description = "Detects vulnerabilities related to program upgrade authority and admin functions";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || 
           filePath.includes("anchor") || 
           filePath.endsWith(".toml") ||
           filePath.includes("Anchor.toml");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Check Anchor.toml for upgrade settings
    if (content.includes('[programs.') || content.includes('program_id =')) {
      // This is Anchor.toml
      const hasUpgradeAuth = content.includes('upgrade_authority');
      const hasMultisig = content.includes('multisig') || 
                         content.includes('threshold') ||
                         content.includes('signers');

      if (hasUpgradeAuth && !hasMultisig) {
        const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "upgrade-authority-attack");
        vulnerabilities.push({
          id: generateVulnerabilityId("single-upgrade-authority", context?.filePath, 0, vulnerabilities.length),
          title: pattern?.name || "Single Upgrade Authority",
          description: pattern?.description || 
            "Program can be upgraded by single authority without multisig",
          severity: Severity.HIGH,
          category: VulnerabilityCategory.GOVERNANCE,
          location: {
            file: context?.filePath,
            line: 0
          },
          recommendation: pattern?.codeExamples.patched || 
            "Use multisig for upgrade authority or make program immutable",
          codeSnippet: 'upgrade_authority = ...',
          references: pattern?.references
        });
      }
    }

    // Pattern 1: Admin functions without timelock
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("fn admin") || 
          line.includes("fn owner") || 
          line.includes("fn authority") || 
          line.includes("fn upgrade") || 
          line.includes("fn migrate")) {
        
        const functionCode = this.extractFunction(content, i);
        const hasTimelock = functionCode.includes('timelock') ||
                           functionCode.includes('delay') ||
                           functionCode.includes('scheduled') ||
                           functionCode.includes('future_slot') ||
                           functionCode.includes('execute_after');

        if (!hasTimelock) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "upgrade-authority-attack");
          vulnerabilities.push({
            id: generateVulnerabilityId("admin-no-timelock", context?.filePath, i + 1, vulnerabilities.length),
            title: "Admin Function Without Timelock",
            description: "Privileged function can be executed immediately without delay",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.GOVERNANCE,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: this.extractFunctionName(content, i)
            },
            recommendation: "Implement timelock for admin operations",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 5).join("\n"),
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Proxy pattern without upgrade limits
      if (line.includes("proxy") || line.includes("implementation") || line.includes("delegate")) {
        if (line.includes("call") || line.includes("invoke")) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "upgrade-authority-attack");
          vulnerabilities.push({
            id: generateVulnerabilityId("proxy-pattern", context?.filePath, i + 1, vulnerabilities.length),
            title: "Proxy Pattern Detected",
            description: "Proxy patterns allow arbitrary code execution if compromised",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.GOVERNANCE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Limit proxy capabilities or use strict access control",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }

  private extractFunction(code: string, lineIndex: number): string {
    const lines = code.split("\n");
    let before = lineIndex;
    while (before > 0 && !lines[before].includes("fn ") && !lines[before].includes("pub fn ")) {
      before--;
    }
    
    let after = lineIndex;
    let braceCount = 0;
    while (after < lines.length) {
      const line = lines[after];
      braceCount += (line.match(/\{/g) || []).length;
      braceCount -= (line.match(/\}/g) || []).length;
      if (braceCount === 0 && after > lineIndex) break;
      after++;
    }
    
    return lines.slice(before, after + 1).join("\n");
  }

  private extractFunctionName(code: string, lineIndex: number): string {
    const beforeMatch = code.substring(0, code.split("\n").slice(0, lineIndex + 1).join("\n").length);
    const fnMatch = beforeMatch.match(/(?:pub\s+)?fn\s+(\w+)/g);
    return fnMatch && fnMatch.length > 0 
      ? fnMatch[fnMatch.length - 1].match(/fn\s+(\w+)/)?.[1] || 'unknown'
      : 'unknown';
  }
}
