import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects MEV/front-running vulnerabilities
 * Identifies swap functions without slippage protection, auctions without commit-reveal, etc.
 */
export class MEVFrontrunningDetector extends BaseDetector {
  name = "MEV/Front-running";
  description = "Detects vulnerabilities that enable MEV attacks like sandwich attacks and front-running";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Swap/Trade without slippage protection
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("fn swap") || line.includes("fn trade") || line.includes("fn exchange")) {
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
        
        const hasSlippageCheck = functionBody.includes('min_amount_out') ||
                                functionBody.includes('max_amount_in') ||
                                functionBody.includes('slippage') ||
                                functionBody.includes('price_impact') ||
                                functionBody.includes('min_output');

        if (!hasSlippageCheck) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "mev-frontrunning");
          vulnerabilities.push({
            id: generateVulnerabilityId("mev-no-slippage", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Swap Without Slippage Protection",
            description: pattern?.description || 
              "Trade function vulnerable to sandwich attacks due to missing slippage limits",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ORACLE_MANIPULATION,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: this.extractFunctionName(content, i)
            },
            recommendation: pattern?.codeExamples.patched || 
              "Add min_amount_out parameter to protect against sandwich attacks",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 10).join("\n"),
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Auction/Bid without commit-reveal
      if (line.includes("auction") || line.includes("bid") || line.includes("offer")) {
        if (line.includes("amount") || line.includes("price")) {
          const functionCode = this.extractFunction(content, i);
          const hasCommitReveal = functionCode.includes('commit') ||
                                 functionCode.includes('reveal') ||
                                 functionCode.includes('sealed') ||
                                 functionCode.includes('encrypted') ||
                                 functionCode.includes('hash');

          if (!hasCommitReveal) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "mev-frontrunning");
            vulnerabilities.push({
              id: generateVulnerabilityId("mev-auction", context?.filePath, i + 1, vulnerabilities.length),
              title: "Auction Without Commit-Reveal",
              description: "Auction/bidding mechanism vulnerable to front-running",
              severity: Severity.MEDIUM,
              category: VulnerabilityCategory.ORACLE_MANIPULATION,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Implement commit-reveal scheme for fair auctions",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 5).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: First-come-first-serve rewards
      if (line.includes("claim") || line.includes("mint") || line.includes("reward")) {
        if (line.includes("first") || line.includes("available") || line.includes("remaining")) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "mev-frontrunning");
          vulnerabilities.push({
            id: generateVulnerabilityId("mev-fcfs", context?.filePath, i + 1, vulnerabilities.length),
            title: "First-Come-First-Serve Mechanism",
            description: "FCFS distribution vulnerable to MEV bots",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.ORACLE_MANIPULATION,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Use lottery, commit-reveal, or time-weighted distribution",
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
