import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Enhanced reentrancy detector
 * Detects multiple patterns of reentrancy vulnerabilities
 */
export class ReentrancyEnhancedDetector extends BaseDetector {
  name = "Reentrancy (Enhanced)";
  description = "Detects reentrancy vulnerabilities including state changes after CPI, missing guards, and transfer-before-validation";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: State change after CPI
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("invoke") || line.includes("invoke_signed") || line.includes("cpi::")) {
        // Look for state changes after the invoke
        const afterCode = lines.slice(i, Math.min(i + 15, lines.length)).join("\n");
        
        // Check for state modifications after invoke
        const hasStateChange = afterCode.match(/(?:state|balance|amount|counter|total|count)\s*[=+\-]/);
        
        if (hasStateChange) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "reentrancy");
          vulnerabilities.push({
            id: generateVulnerabilityId("reentrancy-state", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "State Change After External Call",
            description: pattern?.description || 
              "Modifying state after CPI call creates reentrancy vulnerability",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.REENTRANCY,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: this.extractFunctionName(content, i)
            },
            recommendation: pattern?.codeExamples.patched || 
              "Apply checks-effects-interactions pattern: update state before CPI",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 10).join("\n"),
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Transfer before validation
      if (line.includes("transfer") || line.includes("send")) {
        const afterCode = lines.slice(i, Math.min(i + 10, lines.length)).join("\n");
        const hasValidationAfter = afterCode.includes('require!') ||
                                  afterCode.includes('assert!') ||
                                  afterCode.includes('if') && afterCode.includes('return');

        if (hasValidationAfter) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "reentrancy");
          vulnerabilities.push({
            id: generateVulnerabilityId("reentrancy-transfer", context?.filePath, i + 1, vulnerabilities.length),
            title: "Transfer Before Validation",
            description: "Transferring funds before completing all validations",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.REENTRANCY,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Complete all validations before transferring funds",
            codeSnippet: lines.slice(Math.max(0, i - 3), i + 8).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    // Pattern 3: Functions with invoke but no reentrancy guard
    const functionPattern = /(?:pub\s+)?fn\s+(\w+)/g;
    let match;
    while ((match = functionPattern.exec(content)) !== null) {
      const functionName = match[1];
      const functionStart = match.index;
      
      // Find function body
      let braceCount = 0;
      let functionEnd = functionStart;
      let foundOpen = false;
      
      for (let i = functionStart; i < content.length; i++) {
        if (content[i] === '{') {
          braceCount++;
          foundOpen = true;
        } else if (content[i] === '}') {
          braceCount--;
          if (foundOpen && braceCount === 0) {
            functionEnd = i;
            break;
          }
        }
      }
      
      const functionBody = content.substring(functionStart, functionEnd);
      
      if (functionBody.includes("invoke") || functionBody.includes("invoke_signed")) {
        const hasGuard = functionBody.includes('reentrancy_guard') ||
                        functionBody.includes('require!(!') ||
                        functionBody.includes('is_reentrant') ||
                        content.includes('#[non_reentrant]') ||
                        functionBody.includes('non_reentrant');

        if (!hasGuard) {
          const lineNumber = content.substring(0, functionStart).split("\n").length;
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "reentrancy");
          vulnerabilities.push({
            id: generateVulnerabilityId("reentrancy-no-guard", context?.filePath, lineNumber, vulnerabilities.length),
            title: "Function Without Reentrancy Guard",
            description: `Function ${functionName} makes external calls without reentrancy protection`,
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.REENTRANCY,
            location: {
              file: context?.filePath,
              line: lineNumber,
              function: functionName
            },
            recommendation: "Add reentrancy guard or use checks-effects-interactions pattern",
            codeSnippet: functionBody.substring(0, 200) + '...',
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
