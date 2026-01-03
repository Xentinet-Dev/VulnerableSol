import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects Token-2022 specific vulnerabilities
 * Token-2022 has additional features that require special handling
 */
export class Token2022Detector extends BaseDetector {
  name = "Token-2022 Specific Vulnerabilities";
  description = "Detects vulnerabilities specific to Token-2022 program features";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Missing transfer hook handling
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("token_2022::instruction::transfer") ||
          line.includes("token_2022::instruction::transfer_checked")) {
        
        // Check if transfer hook is handled
        const afterCode = lines.slice(i, Math.min(i + 30, lines.length)).join("\n");
        const hasHookHandling = afterCode.includes('TransferHook') || 
                               afterCode.includes('execute_transfer_hook') ||
                               afterCode.includes('additional_required_accounts') ||
                               afterCode.includes('transfer_hook');

        if (!hasHookHandling) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "token-2022-hooks");
          vulnerabilities.push({
            id: generateVulnerabilityId("token2022-hook", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Missing Token-2022 Transfer Hook Support",
            description: pattern?.description || 
              "Token-2022 transfer without checking for and executing transfer hooks",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Check for transfer hooks and include additional required accounts",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
            metadata: {
              vulnerabilityType: 'token-2022-hooks',
              feature: 'transfer-hooks'
            },
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Ignoring confidential transfer state
      if (line.includes(".amount") && 
          (line.includes("token_account") || line.includes("TokenAccount"))) {
        
        const beforeCode = lines.slice(Math.max(0, i - 20), i).join("\n");
        const afterCode = lines.slice(i, Math.min(i + 10, lines.length)).join("\n");
        if (beforeCode.includes("token_2022") || beforeCode.includes("TokenAccount")) {
          const hasConfidentialCheck = beforeCode.includes('confidential_transfer') ||
                                      beforeCode.includes('available_balance') ||
                                      beforeCode.includes('decryptable_balance') ||
                                      afterCode.includes('available_balance');

          if (!hasConfidentialCheck) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "token-2022-confidential");
            vulnerabilities.push({
              id: generateVulnerabilityId("token2022-confidential", context?.filePath, i + 1, vulnerabilities.length),
              title: "Ignoring Confidential Transfer Balance",
              description: "Reading token amount without considering confidential balance",
              severity: Severity.MEDIUM,
              category: VulnerabilityCategory.ARITHMETIC,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Use available_balance for Token-2022 accounts with confidential transfers",
              codeSnippet: lines.slice(Math.max(0, i - 3), i + 3).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: Missing extension checks
      if (line.includes("get_mint_info") || 
          line.includes("unpack") && line.includes("Mint")) {
        
        const afterCode = lines.slice(i, Math.min(i + 20, lines.length)).join("\n");
        const hasExtensionCheck = afterCode.includes('get_extension') ||
                                 afterCode.includes('extension_types') ||
                                 afterCode.includes('get_mint_extension') ||
                                 afterCode.includes('ExtensionType');

        if (!hasExtensionCheck) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "token-2022-extensions");
          vulnerabilities.push({
            id: generateVulnerabilityId("token2022-extensions", context?.filePath, i + 1, vulnerabilities.length),
            title: "Not Checking Token-2022 Extensions",
            description: "Processing mint without checking for Token-2022 extensions",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Check mint extensions before processing",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}
