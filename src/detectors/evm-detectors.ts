import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects reentrancy vulnerabilities in Solidity contracts
 */
export class ReentrancyDetector extends BaseDetector {
  name = "Reentrancy Vulnerability";
  description = "Detects functions that make external calls before updating state (CEI violation)";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".sol");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern: External call before state update
    const externalCallPatterns = [
      /\.call\s*\{/,
      /\.send\s*\(/,
      /\.transfer\s*\(/,
      /\.call\(/,
      /external\s+call/i
    ];

    const stateUpdatePatterns = [
      /=\s*0/,
      /-\s*=/,
      /\+\s*=/,
      /balances\[/,
      /mapping.*\[.*\]\s*=/
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Check if this is a function that might have reentrancy
      if (line.includes("function") && (line.includes("public") || line.includes("external"))) {
        const functionName = line.match(/function\s+(\w+)/)?.[1];
        if (!functionName) continue;

        // Find the function body
        let braceCount = 0;
        let inFunction = false;
        let externalCallLine = -1;
        let stateUpdateLine = -1;

        for (let j = i; j < lines.length; j++) {
          const currentLine = lines[j];
          
          if (currentLine.includes("{")) {
            braceCount++;
            inFunction = true;
          }
          if (currentLine.includes("}")) {
            braceCount--;
            if (braceCount === 0 && inFunction) {
              break;
            }
          }

          if (inFunction) {
            // Check for external calls
            if (externalCallLine === -1 && externalCallPatterns.some(pattern => pattern.test(currentLine))) {
              externalCallLine = j;
            }

            // Check for state updates
            if (stateUpdateLine === -1 && stateUpdatePatterns.some(pattern => pattern.test(currentLine))) {
              stateUpdateLine = j;
            }
          }
        }

        // If external call happens before state update, it's vulnerable
        if (externalCallLine !== -1 && stateUpdateLine !== -1 && externalCallLine < stateUpdateLine) {
          // Check if there's a reentrancy guard
          let hasGuard = false;
          for (let k = i; k < Math.min(i + 10, lines.length); k++) {
            if (lines[k].includes("nonReentrant") || lines[k].includes("ReentrancyGuard")) {
              hasGuard = true;
              break;
            }
          }

          if (!hasGuard) {
            vulnerabilities.push({
              id: generateVulnerabilityId(`reentrancy-${functionName}`, context?.filePath, i + 1, vulnerabilities.length),
              title: "Reentrancy Vulnerability",
              description: `Function '${functionName}' makes an external call before updating state, violating the Checks-Effects-Interactions pattern.`,
              severity: Severity.CRITICAL,
              category: VulnerabilityCategory.REENTRANCY,
              location: {
                file: context?.filePath,
                line: i + 1,
                function: functionName
              },
              recommendation: "Follow the Checks-Effects-Interactions pattern: 1) Perform checks, 2) Update state, 3) Make external calls. Also consider using OpenZeppelin's ReentrancyGuard modifier.",
              codeSnippet: lines.slice(Math.max(0, externalCallLine - 2), stateUpdateLine + 2).join("\n")
            });
          }
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects weak oracle implementations
 */
export class WeakOracleDetector extends BaseDetector {
  name = "Weak Oracle Implementation";
  description = "Detects single-source or manipulable price oracles";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".sol");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Look for getReserves or similar single-source price calculations
    const oraclePatterns = [
      /getReserves\s*\(/,
      /getPrice\s*\(/,
      /\.price\s*=/,
      /reserve0.*reserve1/
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (oraclePatterns.some(pattern => pattern.test(line))) {
        // Check if it's using TWAP or Chainlink
        let usesTWAP = false;
        let usesChainlink = false;

        // Look in surrounding context
        for (let j = Math.max(0, i - 20); j < Math.min(i + 20, lines.length); j++) {
          if (lines[j].includes("TWAP") || lines[j].includes("twap")) {
            usesTWAP = true;
          }
          if (lines[j].includes("Chainlink") || lines[j].includes("AggregatorV3Interface")) {
            usesChainlink = true;
          }
        }

        if (!usesTWAP && !usesChainlink) {
          const functionName = this.findFunctionName(lines, i);
          vulnerabilities.push({
            id: generateVulnerabilityId("weak-oracle", context?.filePath, i + 1, vulnerabilities.length),
            title: "Weak Oracle Implementation",
            description: `Price calculation appears to use a single-source DEX price without TWAP or Chainlink. This can be manipulated with flash loans.`,
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ORACLE_MANIPULATION,
            location: {
              file: context?.filePath,
              line: i + 1,
              function: functionName
            },
            recommendation: "Use a Time-Weighted Average Price (TWAP) oracle or a decentralized oracle network like Chainlink. Add sanity checks to ensure prices are within reasonable bounds.",
            codeSnippet: lines.slice(Math.max(0, i - 5), i + 5).join("\n")
          });
        }
      }
    }

    return vulnerabilities;
  }

  private findFunctionName(lines: string[], lineIndex: number): string {
    for (let i = lineIndex; i >= 0; i--) {
      const match = lines[i].match(/function\s+(\w+)/);
      if (match) return match[1];
    }
    return "unknown";
  }
}

