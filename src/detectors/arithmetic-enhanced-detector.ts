import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Enhanced arithmetic vulnerability detector
 * Detects precision loss, unsafe casting, exponential operations, and percentage calculations
 */
export class ArithmeticEnhancedDetector extends BaseDetector {
  name = "Arithmetic Vulnerabilities (Enhanced)";
  description = "Detects precision loss, unsafe casting, exponential operations, and percentage calculation vulnerabilities";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Multiplication before division (precision loss)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Skip comments
      if (line.trim().startsWith("//") || line.trim().startsWith("/*")) {
        continue;
      }

      // Check for a * b / c pattern
      const mulDivPattern = /(\w+)\s*\*\s*(\w+)\s*\/\s*(\w+)/;
      if (mulDivPattern.test(line)) {
        const beforeCode = lines.slice(Math.max(0, i - 10), i).join("\n");
        if (!beforeCode.includes('checked_mul') && 
            !beforeCode.includes('u128') && 
            !beforeCode.includes('U256') &&
            !beforeCode.includes('checked_div')) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "precision-loss");
          vulnerabilities.push({
            id: generateVulnerabilityId("precision-loss", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Precision Loss: Multiplication Before Division",
            description: pattern?.description || 
              "Performing multiplication before division can cause precision loss and overflow",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.ARITHMETIC,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Use higher precision types or reorder to (a * c) / b = a * (c / b)",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
            metadata: {
              pattern: 'mul-before-div'
            },
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Unsafe casting
      const castPattern = /(\w+)\s+as\s+(u32|u16|u8|i32|i16|i8)/;
      if (castPattern.test(line)) {
        const match = line.match(castPattern);
        if (match) {
          const sourceVar = match[1];
          const targetType = match[2];
          const beforeCode = lines.slice(Math.max(0, i - 20), i).join("\n");
          
          // Check if source is likely larger type
          if ((beforeCode.includes(`${sourceVar}: u64`) || 
               beforeCode.includes(`${sourceVar}: u128`) ||
               beforeCode.includes(`let ${sourceVar}`) && (beforeCode.includes('u64') || beforeCode.includes('u128'))) &&
              !beforeCode.includes('try_into') && 
              !beforeCode.includes('min(') && 
              !beforeCode.includes('max(') &&
              !beforeCode.includes('checked_cast')) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "cast-truncation");
            vulnerabilities.push({
              id: generateVulnerabilityId("unsafe-cast", context?.filePath, i + 1, vulnerabilities.length),
              title: "Unsafe Type Cast - Potential Truncation",
              description: `Casting from larger type to ${targetType} without bounds check`,
              severity: Severity.HIGH,
              category: VulnerabilityCategory.ARITHMETIC,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Use try_into() or verify value fits in target type",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: Exponential operations
      if (line.includes(".pow(")) {
        const powMatch = line.match(/\.pow\s*\(([^)]+)\)/);
        if (powMatch) {
          const exponent = powMatch[1].trim();
          // Check if exponent is variable or large constant
          if (!exponent.match(/^\d+$/) || (exponent.match(/^\d+$/) && parseInt(exponent) > 10)) {
            const beforeCode = lines.slice(Math.max(0, i - 5), i).join("\n");
            if (!beforeCode.includes('checked_pow')) {
              const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "integer-overflow");
              vulnerabilities.push({
                id: generateVulnerabilityId("unsafe-pow", context?.filePath, i + 1, vulnerabilities.length),
                title: "Unsafe Exponential Operation",
                description: "Power operation with variable or large exponent can overflow",
                severity: Severity.MEDIUM,
                category: VulnerabilityCategory.ARITHMETIC,
                location: {
                  file: context?.filePath,
                  line: i + 1
                },
                recommendation: "Use checked_pow() or limit exponent range",
                codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
                references: pattern?.references
              });
            }
          }
        }
      }

      // Pattern 4: Percentage calculations
      if (line.includes("* 100") || line.includes("/ 100")) {
        const percentMatch = line.match(/(\w+)\s*[*\/]\s*100/);
        if (percentMatch) {
          const afterCode = lines.slice(i, Math.min(i + 5, lines.length)).join("\n");
          // Check if it's multiplying by 100 (overflow risk)
          if (line.includes('* 100') && !afterCode.includes('/ 100')) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "precision-loss");
            vulnerabilities.push({
              id: generateVulnerabilityId("percent-overflow", context?.filePath, i + 1, vulnerabilities.length),
              title: "Percentage Calculation Overflow Risk",
              description: "Multiplying by 100 before dividing can overflow",
              severity: Severity.LOW,
              category: VulnerabilityCategory.ARITHMETIC,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Use basis points (10000) or reorder calculation",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
              references: pattern?.references
            });
          }
        }
      }
    }

    return vulnerabilities;
  }
}
