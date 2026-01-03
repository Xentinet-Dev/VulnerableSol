import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects oracle manipulation vulnerabilities
 * Identifies when oracle prices are used without proper validation
 */
export class OracleManipulationDetector extends BaseDetector {
  name = "Oracle Manipulation";
  description = "Detects when oracle prices are used without proper validation, making them vulnerable to manipulation";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Direct price usage without validation
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("price") || line.includes("rate") || line.includes("value")) {
        if (line.includes("oracle") || line.includes("price_account") || line.includes("price_feed")) {
          // Check if price is used directly
          if (line.includes("=") && (line.includes(".price") || line.includes(".data") || line.includes(".value"))) {
            const afterCode = lines.slice(i, Math.min(i + 20, lines.length)).join("\n");
            const hasValidation = afterCode.includes('confidence') ||
                                 afterCode.includes('staleness') ||
                                 afterCode.includes('timestamp') ||
                                 afterCode.includes('verify_price') ||
                                 afterCode.includes('PriceStatus') ||
                                 afterCode.includes('check_price');

            if (!hasValidation) {
              const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "oracle-manipulation");
              vulnerabilities.push({
                id: generateVulnerabilityId("oracle-no-validation", context?.filePath, i + 1, vulnerabilities.length),
                title: pattern?.name || "Oracle Price Used Without Validation",
                description: pattern?.description || 
                  "Using oracle price without checking confidence interval or staleness",
                severity: Severity.HIGH,
                category: VulnerabilityCategory.ORACLE_MANIPULATION,
                location: {
                  file: context?.filePath,
                  line: i + 1
                },
                recommendation: pattern?.codeExamples.patched || 
                  "Check price confidence interval and staleness before use",
                codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
                references: pattern?.references
              });
            }
          }
        }
      }

      // Pattern 2: Pyth oracle specific checks
      if (line.includes("pyth") || line.includes("price_feed")) {
        if (line.includes("get_price") || line.includes("price_account")) {
          const afterCode = lines.slice(i, Math.min(i + 15, lines.length)).join("\n");
          const hasStatusCheck = afterCode.includes('status') ||
                                afterCode.includes('PriceStatus::Trading') ||
                                afterCode.includes('PriceStatus::Trading');

          if (!hasStatusCheck) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "oracle-manipulation");
            vulnerabilities.push({
              id: generateVulnerabilityId("pyth-no-status", context?.filePath, i + 1, vulnerabilities.length),
              title: "Pyth Oracle Status Not Checked",
              description: "Not checking if Pyth price status is Trading",
              severity: Severity.MEDIUM,
              category: VulnerabilityCategory.ORACLE_MANIPULATION,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Check price_account.status == PriceStatus::Trading",
              codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: No TWAP implementation for swaps
      if (line.includes("swap") || line.includes("exchange") || line.includes("trade")) {
        if (line.includes("amount") && line.includes("price")) {
          const functionCode = this.extractFunction(content, i);
          const hasTWAP = functionCode.includes('twap') ||
                        functionCode.includes('time_weighted') ||
                        functionCode.includes('average_price') ||
                        functionCode.includes('price_history');

          if (!hasTWAP) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "oracle-manipulation");
            vulnerabilities.push({
              id: generateVulnerabilityId("no-twap", context?.filePath, i + 1, vulnerabilities.length),
              title: "No Time-Weighted Average Price (TWAP)",
              description: "Using spot price for swaps without TWAP protection",
              severity: Severity.MEDIUM,
              category: VulnerabilityCategory.ORACLE_MANIPULATION,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Implement TWAP to prevent flash loan price manipulation",
              codeSnippet: lines.slice(Math.max(0, i - 3), i + 5).join("\n"),
              references: pattern?.references
            });
          }
        }
      }
    }

    // Pattern 4: Single oracle source (check entire file)
    const oracleAccountPattern = /oracle[_\s]*(?:account|address|pubkey)/gi;
    const oracleMatches = [...content.matchAll(oracleAccountPattern)];
    
    if (oracleMatches.length === 1) {
      const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "oracle-manipulation");
      vulnerabilities.push({
        id: generateVulnerabilityId("single-oracle-source", context?.filePath, 0, vulnerabilities.length),
        title: "Single Oracle Dependency",
        description: "Relying on single oracle source is vulnerable to manipulation",
        severity: Severity.HIGH,
        category: VulnerabilityCategory.ORACLE_MANIPULATION,
        location: {
          file: context?.filePath,
          line: 0
        },
        recommendation: "Use multiple oracle sources or implement TWAP",
        codeSnippet: oracleMatches[0][0],
        references: pattern?.references
      });
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
}
