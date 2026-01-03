import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects cast truncation vulnerabilities
 * Based on: solana-hacks/cast_truncation
 */
export class CastTruncationDetector extends BaseDetector {
  name = "Cast Truncation";
  description = "Detects unsafe type casts that could truncate values";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Patterns for unsafe casts: larger type to smaller type
    const truncationPatterns = [
      /(\w+)\s+as\s+u8/,      // u64/u32/u16 as u8
      /(\w+)\s+as\s+u16/,     // u64/u32 as u16
      /(\w+)\s+as\s+u32/,     // u64/u128 as u32
      /(\w+)\s+as\s+i8/,      // i64/i32/i16 as i8
      /(\w+)\s+as\s+i16/,     // i64/i32 as i16
      /(\w+)\s+as\s+i32/,     // i64/i128 as i32
    ];

    // Type size mapping (larger to smaller = truncation risk)
    const typeSizes: { [key: string]: number } = {
      'u8': 1, 'i8': 1,
      'u16': 2, 'i16': 2,
      'u32': 4, 'i32': 4,
      'u64': 8, 'i64': 8,
      'u128': 16, 'i128': 16,
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Skip comments
      if (line.trim().startsWith("//") || line.trim().startsWith("/*")) {
        continue;
      }

      for (const pattern of truncationPatterns) {
        if (pattern.test(line)) {
          // Check if it's in an arithmetic or assignment context
          const isInArithmeticContext = 
            line.includes("=") || 
            line.includes("+") || 
            line.includes("-") || 
            line.includes("*") ||
            line.includes("/") ||
            line.includes("return");

          if (isInArithmeticContext) {
            // Check if there's a checked cast or validation
            let hasValidation = false;
            
            // Look ahead/behind for validation
            for (let j = Math.max(0, i - 5); j < Math.min(i + 5, lines.length); j++) {
              if (lines[j].includes("checked_cast") || 
                  lines[j].includes("try_into") ||
                  lines[j].includes("saturating_cast") ||
                  (lines[j].includes("require") && lines[j].includes("<="))) {
                hasValidation = true;
                break;
              }
            }

            if (!hasValidation) {
              vulnerabilities.push({
                id: generateVulnerabilityId("cast-truncation", context?.filePath, i + 1, vulnerabilities.length),
                title: "Cast Truncation",
                description: `Unsafe type cast at line ${i + 1} could truncate values, leading to incorrect calculations or overflow bypass.`,
                severity: Severity.HIGH,
                category: VulnerabilityCategory.ARITHMETIC,
                location: {
                  file: context?.filePath,
                  line: i + 1
                },
                recommendation: "Use checked_cast() or try_into() with proper error handling, or validate the value is within the target type's range before casting.",
                codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
                references: ["https://github.com/hackermystique/solana-hacks/tree/main/cast_truncation"]
              });
              break;
            }
          }
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects close account vulnerabilities
 * Based on: solana-hacks/close-account
 */
export class CloseAccountDetector extends BaseDetector {
  name = "Close Account Vulnerability";
  description = "Detects unsafe account closing operations";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for close operations
      if (line.includes(".close(") || line.includes("close_account")) {
        // Find the function this is in
        let functionStart = -1;
        for (let j = i; j >= 0; j--) {
          if (lines[j].includes("fn ") || lines[j].includes("pub fn ")) {
            functionStart = j;
            break;
          }
        }

        // Check for authorization
        let hasAuthorization = false;
        let hasOwnerCheck = false;
        
        // Look in function for authorization checks
        for (let j = functionStart; j < Math.min(functionStart + 100, lines.length); j++) {
          if (lines[j].includes("require!") && 
              (lines[j].includes("owner") || 
               lines[j].includes("authority") || 
               lines[j].includes("admin") ||
               lines[j].includes("Signer"))) {
            hasAuthorization = true;
          }
          
          if (lines[j].includes(".owner") && lines[j].includes("==")) {
            hasOwnerCheck = true;
          }

          if (lines[j].includes("}") && lines[j].trim() === "}") {
            break;
          }
        }

        // Check if account is in a Signer context (Anchor auto-validates)
        let usesSigner = false;
        for (let j = Math.max(0, i - 50); j < i; j++) {
          if (lines[j].includes("Signer<'info>") && 
              (lines[j].includes("authority") || lines[j].includes("admin") || lines[j].includes("owner"))) {
            usesSigner = true;
            break;
          }
        }

        if (!hasAuthorization && !hasOwnerCheck && !usesSigner) {
          vulnerabilities.push({
            id: generateVulnerabilityId("close-account", context?.filePath, i + 1, vulnerabilities.length),
            title: "Close Account Vulnerability",
            description: `Account close operation at line ${i + 1} without proper authorization check. An attacker could close accounts they don't own.`,
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Always verify the account owner or use a Signer constraint before closing accounts. Ensure rent is reclaimed to the correct account.",
            codeSnippet: lines.slice(Math.max(0, i - 5), i + 3).join("\n"),
            references: ["https://github.com/hackermystique/solana-hacks/tree/main/close-account"]
          });
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects duplicated mutable accounts
 * Based on: solana-hacks/duplicated
 */
export class DuplicatedAccountDetector extends BaseDetector {
  name = "Duplicated Mutable Accounts";
  description = "Detects when the same account appears multiple times in a context";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Find Context structs
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("#[derive(Accounts)]")) {
        // Find the struct definition
        let structStart = -1;
        for (let j = i; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes("pub struct") && lines[j].includes("Context")) {
            structStart = j;
            break;
          }
        }

        if (structStart === -1) continue;

        // Collect all mutable accounts
        const mutableAccounts: string[] = [];
        const accountKeys: string[] = [];
        
        for (let j = structStart; j < Math.min(structStart + 50, lines.length); j++) {
          const structLine = lines[j];
          
          if (structLine.includes("#[account(mut)")) {
            // Extract account name
            const nameMatch = structLine.match(/pub\s+(\w+):/);
            if (nameMatch) {
              mutableAccounts.push(nameMatch[1]);
            }
          }

          // Also collect account keys for comparison
          if (structLine.includes("pub ") && structLine.includes("Account")) {
            const keyMatch = structLine.match(/pub\s+(\w+):/);
            if (keyMatch) {
              accountKeys.push(keyMatch[1]);
            }
          }

          if (structLine.includes("}") && structLine.trim().startsWith("}")) {
            break;
          }
        }

        // Check for duplicates (same account name or key)
        const seen = new Set<string>();
        for (const account of mutableAccounts) {
          if (seen.has(account)) {
            vulnerabilities.push({
              id: generateVulnerabilityId("duplicated-account", context?.filePath, i + 1, vulnerabilities.length),
              title: "Duplicated Mutable Account",
              description: `Account '${account}' appears multiple times in the context struct. This could lead to state corruption if the same account is used twice.`,
              severity: Severity.HIGH,
              category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Ensure all accounts in a context are unique. Add constraints like `constraint = account_a.key() != account_b.key()` to prevent duplicate accounts.",
              codeSnippet: lines.slice(Math.max(0, i - 2), structStart + 20).join("\n"),
              references: ["https://github.com/hackermystique/solana-hacks/tree/main/duplicated"]
            });
          }
          seen.add(account);
        }

        // Check if there's a constraint preventing duplicates
        let hasDuplicatePrevention = false;
        for (let j = structStart; j < Math.min(structStart + 50, lines.length); j++) {
          if (lines[j].includes("constraint") && 
              (lines[j].includes("!=") || lines[j].includes("key()"))) {
            hasDuplicatePrevention = true;
            break;
          }
        }

        // If we have multiple mutable accounts but no constraint, warn
        if (mutableAccounts.length > 1 && !hasDuplicatePrevention) {
          vulnerabilities.push({
            id: generateVulnerabilityId("potential-duplicate", context?.filePath, i + 1, vulnerabilities.length),
            title: "Potential Duplicated Accounts",
            description: `Multiple mutable accounts found without duplicate prevention constraints. Consider adding constraints to ensure accounts are unique.`,
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Add constraints to prevent the same account from being passed twice: `constraint = account_a.key() != account_b.key()`",
            codeSnippet: lines.slice(Math.max(0, i - 2), structStart + 20).join("\n"),
            references: ["https://github.com/hackermystique/solana-hacks/tree/main/duplicated"]
          });
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects error handling issues
 * Based on: solana-hacks/error-not-handled
 */
export class ErrorHandlingDetector extends BaseDetector {
  name = "Error Not Handled";
  description = "Detects unsafe error handling patterns";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Patterns for unsafe error handling
    const unsafePatterns = [
      /\.unwrap\(\)/,
      /\.expect\(/,
      /\.unwrap_or\(/,
      /panic!/,
      /unreachable!/
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Skip comments and tests
      if (line.trim().startsWith("//") || 
          line.trim().startsWith("/*") ||
          line.includes("#[test]") ||
          line.includes("#[cfg(test)]")) {
        continue;
      }

      for (const pattern of unsafePatterns) {
        if (pattern.test(line)) {
          // Check if it's in a test context (tests can use unwrap)
          let isInTest = false;
          for (let j = Math.max(0, i - 20); j < i; j++) {
            if (lines[j].includes("#[test]") || 
                lines[j].includes("#[cfg(test)]") ||
                lines[j].includes("mod tests")) {
              isInTest = true;
              break;
            }
          }

          if (!isInTest) {
            vulnerabilities.push({
              id: generateVulnerabilityId("error-handling", context?.filePath, i + 1, vulnerabilities.length),
              title: "Unsafe Error Handling",
              description: `Unsafe error handling at line ${i + 1} (${pattern.source}). This could cause the program to panic and fail transactions unexpectedly.`,
              severity: Severity.HIGH,
              category: VulnerabilityCategory.LOGIC_ERROR,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Use proper error handling with `?` operator or `match` statements. Return `Result` types and handle errors gracefully.",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
              references: ["https://github.com/hackermystique/solana-hacks/tree/main/error-not-handled"]
            });
            break;
          }
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects inconsistent rounding issues
 * Based on: solana-hacks/other-bugs (Inconsistent rounding)
 */
export class RoundingDetector extends BaseDetector {
  name = "Inconsistent Rounding";
  description = "Detects division operations that may round incorrectly";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Look for division operations
    const divisionPattern = /(\w+)\s*\/\s*(\w+)/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Skip comments
      if (line.trim().startsWith("//") || line.trim().startsWith("/*")) {
        continue;
      }

      if (divisionPattern.test(line)) {
        // Check if it's in a financial/calculation context
        const isFinancialContext = 
          line.includes("amount") ||
          line.includes("balance") ||
          line.includes("price") ||
          line.includes("rate") ||
          line.includes("fee") ||
          line.includes("percent") ||
          line.includes("share");

        if (isFinancialContext) {
          // Check for proper rounding
          let hasProperRounding = false;
          
          // Look for rounding patterns
          for (let j = Math.max(0, i - 5); j < Math.min(i + 5, lines.length); j++) {
            if (lines[j].includes("round") ||
                lines[j].includes("ceil") ||
                lines[j].includes("floor") ||
                lines[j].includes("checked_div") ||
                (lines[j].includes("+") && lines[j].includes("/ 2"))) { // Round to nearest
              hasProperRounding = true;
              break;
            }
          }

          if (!hasProperRounding) {
            vulnerabilities.push({
              id: generateVulnerabilityId("rounding", context?.filePath, i + 1, vulnerabilities.length),
              title: "Inconsistent Rounding",
              description: `Division operation at line ${i + 1} may round incorrectly. Integer division always rounds down, which could lead to precision loss or incorrect calculations.`,
              severity: Severity.MEDIUM,
              category: VulnerabilityCategory.ARITHMETIC,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Use proper rounding logic: `(value + divisor / 2) / divisor` for round-to-nearest, or use decimal math libraries for precise calculations.",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
              references: ["https://github.com/hackermystique/solana-hacks/tree/main/other-bugs"]
            });
          }
        }
      }
    }

    return vulnerabilities;
  }
}

