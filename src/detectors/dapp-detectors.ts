import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects supply chain vulnerabilities in frontend code
 */
export class SupplyChainDetector extends BaseDetector {
  name = "Supply Chain Attack";
  description = "Detects potentially compromised or outdated dependencies";

  isApplicable(filePath: string): boolean {
    return filePath.includes("package.json") || 
           filePath.includes("package-lock.json") ||
           filePath.includes("yarn.lock") ||
           filePath.includes("Cargo.toml");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for known vulnerable packages
    const suspiciousPackages = [
      "@suspicious-package",
      "malicious-package",
      "compromised-"
    ];

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const pkg of suspiciousPackages) {
        if (line.includes(pkg)) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "supply-chain-attack");
          vulnerabilities.push({
            id: generateVulnerabilityId("supply-chain", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Supply Chain Attack",
            description: pattern?.description || 
              `Potentially suspicious package detected: ${pkg}`,
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Use only verified, audited packages from official sources. Regularly update dependencies and audit package-lock.json.",
            codeSnippet: line,
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects XSS vulnerabilities in frontend code
 */
export class XSSDetector extends BaseDetector {
  name = "Cross-Site Scripting (XSS)";
  description = "Detects unsafe HTML manipulation that could lead to XSS attacks";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".js") || 
           filePath.endsWith(".jsx") || 
           filePath.endsWith(".ts") || 
           filePath.endsWith(".tsx") ||
           filePath.endsWith(".html") ||
           filePath.includes("inline.html") || // For HTML content from URL scanner
           filePath.startsWith("http"); // For direct URL scans
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    const xssPatterns = [
      /\.innerHTML\s*=/,
      /dangerouslySetInnerHTML/,
      /eval\s*\(/,
      /document\.write/,
      /\.outerHTML\s*=/
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const pattern of xssPatterns) {
        if (pattern.test(line) && !line.includes("sanitize") && !line.includes("DOMPurify")) {
          const patternData = VULNERABILITY_REGISTRY.find(v => v.id === "xss");
          vulnerabilities.push({
            id: generateVulnerabilityId("xss", context?.filePath, i + 1, vulnerabilities.length),
            title: patternData?.name || "Cross-Site Scripting (XSS)",
            description: patternData?.description || 
              `Unsafe HTML manipulation detected that could allow XSS attacks.`,
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: patternData?.codeExamples.patched || 
              "Use textContent instead of innerHTML, or sanitize user input with DOMPurify before rendering.",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
            references: patternData?.references
          });
          break;
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects wallet integration flaws
 */
export class WalletIntegrationDetector extends BaseDetector {
  name = "Wallet Integration Flaws";
  description = "Detects insecure wallet connection patterns";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".js") || 
           filePath.endsWith(".jsx") || 
           filePath.endsWith(".ts") || 
           filePath.endsWith(".tsx") ||
           filePath.includes("inline.html") || // For HTML content from URL scanner
           filePath.startsWith("http"); // For direct URL scans
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Check for wallet operations without proper error handling
    let hasWalletConnection = false;
    let hasErrorHandling = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("window.ethereum") || 
          line.includes("window.solana") || 
          line.includes("wallet.connect") ||
          line.includes("sendTransaction")) {
        hasWalletConnection = true;
      }

      if (line.includes("try") || line.includes("catch") || line.includes("error")) {
        hasErrorHandling = true;
      }
    }

    if (hasWalletConnection && !hasErrorHandling) {
      const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "wallet-integration-flaws");
      vulnerabilities.push({
        id: generateVulnerabilityId("wallet-integration", context?.filePath, 0, vulnerabilities.length),
        title: pattern?.name || "Wallet Integration Flaws",
        description: pattern?.description || 
          "Wallet connection detected without proper error handling. This could lead to user fund loss.",
        severity: Severity.HIGH,
        category: VulnerabilityCategory.ACCESS_CONTROL,
        location: {
          file: context?.filePath
        },
        recommendation: pattern?.codeExamples.patched || 
          "Implement proper error handling and user confirmation for all wallet operations. Validate transaction parameters before submission.",
        references: pattern?.references
      });
    }

    // Check for setApprovalForAll without warnings
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("setApprovalForAll") || line.includes("approveAll")) {
        // Check if there's a user confirmation nearby
        let hasConfirmation = false;
        for (let j = Math.max(0, i - 10); j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes("confirm") || 
              lines[j].includes("warning") || 
              lines[j].includes("alert") ||
              lines[j].includes("user approval")) {
            hasConfirmation = true;
            break;
          }
        }

        if (!hasConfirmation) {
          vulnerabilities.push({
            id: generateVulnerabilityId("wallet-approval", context?.filePath, i + 1, vulnerabilities.length),
            title: "Excessive Wallet Permissions",
            description: "setApprovalForAll called without clear user warning or confirmation.",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Always show a clear warning dialog explaining the risks of approving all tokens before requesting approval."
          });
        }
      }
    }

    return vulnerabilities;
  }
}

