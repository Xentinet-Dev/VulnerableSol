import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects sysvar account spoofing vulnerabilities
 * Based on real-world exploits where attackers provide fake sysvar accounts
 */
export class SysvarSpoofingDetector extends BaseDetector {
  name = "Sysvar Account Spoofing";
  description = "Detects when programs accept sysvar accounts from user input instead of using Clock::get() or Rent::get()";

  // Known sysvar account IDs that should never be user-provided
  private readonly SYSVAR_IDS = [
    'SysvarC1ock11111111111111111111111111111111',
    'SysvarRent111111111111111111111111111111111',
    'SysvarStakeHistory1111111111111111111111111',
    'SysvarRecentB1ockHashes11111111111111111111',
    'SysvarEpochSchedu1e111111111111111111111111',
    'SysvarFees111111111111111111111111111111111',
    'SysvarS1otHashes111111111111111111111111111',
  ];

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Account iterator accepting sysvar accounts
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for Clock::from_account_info or Rent::from_account_info
      if (line.includes("Clock::from_account_info") || 
          line.includes("Rent::from_account_info") ||
          line.includes("StakeHistory::from_account_info")) {
        
        // Check if it's using next_account_info (user-provided)
        let usesNextAccountInfo = false;
        for (let j = Math.max(0, i - 10); j < i; j++) {
          if (lines[j].includes("next_account_info")) {
            usesNextAccountInfo = true;
            break;
          }
        }

        if (usesNextAccountInfo) {
          const sysvarType = this.extractSysvarType(line);
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "sysvar-spoofing");
          vulnerabilities.push({
            id: generateVulnerabilityId("sysvar-spoofing", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Sysvar Account Spoofing Vulnerability",
            description: pattern?.description || 
              `Program accepts ${sysvarType} sysvar account from user input instead of using ${sysvarType}::get(). An attacker can provide a fake sysvar account with manipulated data.`,
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: this.extractFunctionName(content, i)
            },
            recommendation: pattern?.codeExamples.patched || 
              `Use ${sysvarType}::get()? instead of accepting sysvar accounts as input`,
            codeSnippet: lines.slice(Math.max(0, i - 5), i + 3).join("\n"),
            metadata: {
              vulnerabilityType: 'sysvar-spoofing',
              sysvarType: sysvarType
            },
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Checking if account key matches sysvar ID (still vulnerable)
      if (line.includes(".key") && 
          (line.includes("clock") || line.includes("rent") || line.includes("stake_history")) &&
          (line.includes("==") || line.includes("!="))) {
        
        // Check if it's comparing to sysvar ID (insufficient validation)
        const hasSysvarIdCheck = this.SYSVAR_IDS.some(id => 
          line.includes(id) || 
          line.includes("sysvar::clock::id") ||
          line.includes("sysvar::rent::id")
        );

        if (hasSysvarIdCheck) {
          // This is still vulnerable because attacker can create fake account with sysvar ID
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "sysvar-spoofing");
          vulnerabilities.push({
            id: generateVulnerabilityId("sysvar-spoofing-check", context?.filePath, i + 1, vulnerabilities.length),
            title: "Insufficient Sysvar Validation",
            description: "Checking account key == sysvar ID is insufficient. Attacker can create account with same ID but different data",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: this.extractFunctionName(content, i)
            },
            recommendation: "Use Clock::get()? or Rent::get()? instead of manual validation",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 3).join("\n"),
            references: pattern?.references
          });
        }
      }

      // Pattern 3: Invoke/CPI with sysvar accounts
      if (line.includes("invoke") || line.includes("invoke_signed")) {
        // Check if sysvar accounts are being passed
        const beforeCode = lines.slice(Math.max(0, i - 20), i).join("\n");
        if (beforeCode.includes("clock") || beforeCode.includes("rent")) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "sysvar-spoofing");
          vulnerabilities.push({
            id: generateVulnerabilityId("sysvar-spoofing-invoke", context?.filePath, i + 1, vulnerabilities.length),
            title: "Sysvar Passed to Cross-Program Invocation",
            description: "Passing potentially spoofed sysvar account to another program",
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Never pass user-provided sysvar accounts to other programs",
            codeSnippet: lines.slice(Math.max(0, i - 5), i + 3).join("\n"),
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

  private extractSysvarType(snippet: string): string {
    if (snippet.includes("Clock")) return "Clock";
    if (snippet.includes("Rent")) return "Rent";
    if (snippet.includes("StakeHistory")) return "StakeHistory";
    return "Unknown";
  }
}
