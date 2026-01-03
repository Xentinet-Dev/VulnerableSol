import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects address poisoning attack vulnerabilities in frontend/integration code
 * Address poisoning attacks trick users into sending funds to attacker-controlled addresses
 */
export class AddressPoisoningDetector extends BaseDetector {
  name = "Address Poisoning Attack";
  description = "Detects vulnerabilities that enable address poisoning attacks in frontend code";

  isApplicable(filePath: string): boolean {
    // Only for TypeScript/JavaScript frontend code
    return filePath.endsWith(".ts") || 
           filePath.endsWith(".tsx") || 
           filePath.endsWith(".js") || 
           filePath.endsWith(".jsx");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Check if this is TypeScript/JavaScript code
    const isTypeScript = content.includes('import') && 
                        (content.includes('PublicKey') || 
                         content.includes('@solana/web3.js') ||
                         content.includes('transfer') ||
                         content.includes('send'));

    if (!isTypeScript) {
      return vulnerabilities; // Only for TS/JS frontend code
    }

    // Pattern 1: No address validation before transfer
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("transfer") || 
          line.includes("send") || 
          line.includes("withdraw")) {
        
        // Extract recipient variable
        const transferMatch = line.match(/(?:transfer|send|withdraw).*?\(([^,)]+),/);
        if (transferMatch) {
          const recipientVar = transferMatch[1].trim();
          
          // Check if there's validation before this
          const beforeCode = lines.slice(Math.max(0, i - 30), i).join("\n");
          const hasValidation = beforeCode.includes(`validate${recipientVar}`) ||
                               beforeCode.includes(`${recipientVar}.equals`) ||
                               beforeCode.includes('isValidPublicKey') ||
                               beforeCode.includes('PublicKey.isOnCurve') ||
                               beforeCode.includes('validateAddress') ||
                               beforeCode.includes('addressBook') ||
                               beforeCode.includes('savedAddresses');

          if (!hasValidation) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "address-poisoning");
            vulnerabilities.push({
              id: generateVulnerabilityId("address-poison", context?.filePath, i + 1, vulnerabilities.length),
              title: pattern?.name || "No Address Validation Before Transfer",
              description: pattern?.description || 
                "Transferring to address without validation - vulnerable to address poisoning",
              severity: Severity.CRITICAL,
              category: VulnerabilityCategory.ACCESS_CONTROL,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: pattern?.codeExamples.patched || 
                "Validate address format and show full address to user before transfer",
              codeSnippet: lines.slice(Math.max(0, i - 5), i + 3).join("\n"),
              metadata: {
                vulnerabilityType: 'address-poisoning',
                recipientVariable: recipientVar
              },
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 2: Address truncation in UI
      if (line.includes("slice") || line.includes("substring") || line.includes("substr")) {
        const truncateMatch = line.match(/(?:slice|substring|substr)\s*\(\s*\d+\s*,\s*\d+\s*\)/);
        if (truncateMatch) {
          const beforeCode = lines.slice(Math.max(0, i - 5), i).join("\n");
          if (beforeCode.includes("address") || 
              beforeCode.includes("publicKey") || 
              beforeCode.includes("wallet") ||
              beforeCode.includes("PublicKey")) {
            
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "address-poisoning");
            vulnerabilities.push({
              id: generateVulnerabilityId("address-truncate", context?.filePath, i + 1, vulnerabilities.length),
              title: "Address Truncation in UI",
              description: "Showing truncated addresses makes poisoning attacks easier",
              severity: Severity.HIGH,
              category: VulnerabilityCategory.ACCESS_CONTROL,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Show full address or use address book with saved addresses",
              codeSnippet: lines.slice(Math.max(0, i - 3), i + 3).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: Copying addresses from transaction history
      if (line.includes("transaction") || line.includes("history") || line.includes("recent")) {
        if (line.includes(".map") && line.includes("address")) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "address-poisoning");
          vulnerabilities.push({
            id: generateVulnerabilityId("address-history", context?.filePath, i + 1, vulnerabilities.length),
            title: "Address Copying from Transaction History",
            description: "Allowing users to copy addresses from history enables poisoning attacks",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Implement address book instead of relying on transaction history",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 3).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}
