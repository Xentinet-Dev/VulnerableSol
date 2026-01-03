import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects missing signer checks in Solana/Anchor programs
 */
export class MissingSignerCheckDetector extends BaseDetector {
  name = "Missing Signer Check";
  description = "Detects when privileged functions don't verify account signatures";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: Look for AccountInfo in privileged contexts without Signer
    const accountInfoPattern = /pub\s+(\w+):\s+AccountInfo<'info>/g;
    const privilegedFunctions = [
      "withdraw",
      "transfer",
      "change_admin",
      "update_owner",
      "mint",
      "burn",
      "close",
      "withdraw_admin_fees",
      "set_authority"
    ];

    let match;
    let lineNumber = 0;

    for (const line of lines) {
      lineNumber++;

      // Check for privileged function definitions
      const isPrivilegedFunction = privilegedFunctions.some(fn =>
        line.includes(`pub fn ${fn}`) || line.includes(`fn ${fn}`)
      );

      if (isPrivilegedFunction) {
        // Look ahead for AccountInfo usage in the context struct
        let foundAccountInfo = false;
        let foundSigner = false;
        let accountName = "";
        let contextStart = lineNumber;

        // Find the associated Context struct
        for (let i = lineNumber; i < Math.min(lineNumber + 50, lines.length); i++) {
          const currentLine = lines[i];
          
          if (currentLine.includes("#[derive(Accounts)]")) {
            contextStart = i;
          }

          if (currentLine.includes("pub struct") && currentLine.includes("Context")) {
            // Scan this context struct
            for (let j = i; j < Math.min(i + 30, lines.length); j++) {
              const structLine = lines[j];
              
              if (structLine.includes("AccountInfo<'info>")) {
                foundAccountInfo = true;
                const nameMatch = structLine.match(/pub\s+(\w+):\s+AccountInfo/);
                if (nameMatch) {
                  accountName = nameMatch[1];
                }
              }

              if (structLine.includes("Signer<'info>") && accountName) {
                foundSigner = true;
                break;
              }

              if (structLine.includes("}") && structLine.trim().startsWith("}")) {
                break;
              }
            }
            break;
          }
        }

        // Check if AccountInfo is used without Signer in privileged context
        if (foundAccountInfo && !foundSigner && accountName) {
          // Check if there's a manual signer check in the function
          let hasManualCheck = false;
          for (let i = lineNumber; i < Math.min(lineNumber + 100, lines.length); i++) {
            if (lines[i].includes(`is_signer`) || 
                (lines[i].includes(`require!`) && lines[i].includes("signer"))) {
              hasManualCheck = true;
              break;
            }
            if (lines[i].includes("}") && lines[i].trim() === "}") {
              break;
            }
          }

          if (!hasManualCheck) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "missing-signer-check");
            vulnerabilities.push({
              id: generateVulnerabilityId("missing-signer-check", context?.filePath, lineNumber, vulnerabilities.length),
              title: pattern?.name || "Missing Signer Check",
              description: pattern?.description || 
                `The function uses AccountInfo for '${accountName}' without verifying it's a signer. An attacker can pass any account without needing the private key.`,
              severity: Severity.CRITICAL,
              category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
              location: {
                file: context?.filePath,
                line: lineNumber,
                function: line.match(/fn\s+(\w+)/)?.[1]
              },
              recommendation: pattern?.codeExamples.patched || 
                "Use Signer<'info> instead of AccountInfo<'info> for accounts that must sign the transaction. In Anchor, this is: pub admin: Signer<'info>",
              codeSnippet: lines.slice(Math.max(0, lineNumber - 2), lineNumber + 5).join("\n"),
              references: pattern?.references
            });
          }
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects missing ownership checks
 */
export class MissingOwnershipCheckDetector extends BaseDetector {
  name = "Missing Ownership Check";
  description = "Detects when accounts don't verify ownership by expected programs";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Look for AccountInfo used for token accounts or other external accounts
    const tokenAccountPattern = /(token_account|token_account|mint|vault|token_mint|config|admin_account)/i;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("AccountInfo<'info>") && tokenAccountPattern.test(line)) {
        // Check if there's an ownership check nearby
        let hasOwnershipCheck = false;
        
        // Look in the next 20 lines for ownership validation
        for (let j = i; j < Math.min(i + 20, lines.length); j++) {
          if (lines[j].includes(".owner") || 
              lines[j].includes("TokenAccount") ||
              lines[j].includes("spl_token::ID") ||
              lines[j].includes("Account<") ||
              lines[j].includes("require!") && (lines[j].includes("owner") || lines[j].includes("program_id"))) {
            hasOwnershipCheck = true;
            break;
          }
        }

        if (!hasOwnershipCheck) {
          const accountName = line.match(/pub\s+(\w+):/)?.[1] || "unknown";
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "missing-ownership-check");
          vulnerabilities.push({
            id: generateVulnerabilityId("missing-ownership-check", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Missing Ownership Check",
            description: pattern?.description || 
              `Account '${accountName}' uses AccountInfo without verifying ownership. An attacker could pass a fake account owned by a malicious program.`,
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Use Anchor's typed accounts like Account<'info, TokenAccount> which automatically verify ownership, or manually check account.owner == expected_program_id",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects reinitialization vulnerabilities
 */
export class ReinitializationDetector extends BaseDetector {
  name = "Re-initialization Attack";
  description = "Detects when initialization functions can be called multiple times";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Look for initialize functions
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("fn initialize") || line.includes("pub fn initialize")) {
        // Find the associated Context struct
        for (let j = i; j < Math.min(i + 30, lines.length); j++) {
          if (lines[j].includes("#[derive(Accounts)]")) {
            // Check if init constraint is present
            let hasInit = false;
            let hasInitializedFlag = false;
            
            for (let k = j; k < Math.min(j + 30, lines.length); k++) {
              if (lines[k].includes("#[account(init")) {
                hasInit = true;
              }
              if (lines[k].includes("initialized") || lines[k].includes("is_initialized")) {
                hasInitializedFlag = true;
              }
              if (lines[k].includes("}") && lines[k].trim().startsWith("}")) {
                break;
              }
            }

            if (!hasInit && !hasInitializedFlag) {
              const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "reinitialization");
              vulnerabilities.push({
                id: generateVulnerabilityId("reinitialization", context?.filePath, i + 1, vulnerabilities.length),
                title: pattern?.name || "Re-initialization Attack",
                description: pattern?.description || 
                  "Initialize function can be called multiple times, allowing state reset attacks.",
                severity: Severity.CRITICAL,
                category: VulnerabilityCategory.ACCESS_CONTROL,
                location: {
                  file: context?.filePath,
                  line: i + 1,
                  function: "initialize"
                },
                recommendation: pattern?.codeExamples.patched || 
                  "Use Anchor's 'init' constraint or add an 'initialized' flag check to prevent reinitialization.",
                codeSnippet: lines.slice(Math.max(0, i - 2), i + 10).join("\n"),
                references: pattern?.references
              });
            }
            break;
          }
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects integer overflow/underflow vulnerabilities
 */
export class IntegerOverflowDetector extends BaseDetector {
  name = "Integer Overflow/Underflow";
  description = "Detects unchecked arithmetic operations that could overflow";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    const overflowPatterns = [
      /(\w+)\s*\+\s*(\w+)/,  // a + b
      /(\w+)\s*-\s*(\w+)/,    // a - b
      /(\w+)\s*\*\s*(\w+)/,   // a * b
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Skip comments
      if (line.trim().startsWith("//") || line.trim().startsWith("/*")) {
        continue;
      }

      for (const pattern of overflowPatterns) {
        if (pattern.test(line) && 
            !line.includes("checked_add") && 
            !line.includes("checked_sub") && 
            !line.includes("checked_mul") &&
            !line.includes("saturating_")) {
          
          const patternData = VULNERABILITY_REGISTRY.find(v => v.id === "integer-overflow");
          vulnerabilities.push({
            id: generateVulnerabilityId("integer-overflow", context?.filePath, i + 1, vulnerabilities.length),
            title: patternData?.name || "Integer Overflow/Underflow",
            description: patternData?.description || 
              `Unchecked arithmetic operation at line ${i + 1} could overflow or underflow.`,
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ARITHMETIC,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: patternData?.codeExamples.patched || 
              "Use checked arithmetic methods: checked_add(), checked_sub(), checked_mul() with proper error handling.",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
            references: patternData?.references
          });
          break; // Only report once per line
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects PDA abuse vulnerabilities
 */
export class PDAAbuseDetector extends BaseDetector {
  name = "PDA Abuse";
  description = "Detects weak PDA generation or missing canonical bump validation";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for PDA generation
      if (line.includes("find_program_address") || line.includes("Pubkey::create_program_address")) {
        // Check if canonical bump is validated
        let hasBumpCheck = false;
        
        // Look ahead for bump validation
        for (let j = i; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes("bump") && 
              (lines[j].includes("require") || lines[j].includes("assert") || lines[j].includes("=="))) {
            hasBumpCheck = true;
            break;
          }
        }

        if (!hasBumpCheck) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "pda-abuse");
          vulnerabilities.push({
            id: generateVulnerabilityId("pda-abuse", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "PDA Abuse",
            description: pattern?.description || 
              "PDA generation without canonical bump validation could allow attackers to generate unintended PDAs.",
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Always validate that the bump is the canonical bump and store it in the account data.",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 5).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects failure to validate external programs (Type Confusion / Arbitrary CPI)
 */
export class ExternalProgramValidationDetector extends BaseDetector {
  name = "Failure to Validate External Programs";
  description = "Detects when programs are invoked without validating their program ID";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for invoke or invoke_signed calls
      if (line.includes("invoke(") || line.includes("invoke_signed(")) {
        // Check if there's program validation before the invoke
        let hasProgramValidation = false;
        
        // Look backwards for program validation
        for (let j = Math.max(0, i - 30); j < i; j++) {
          const checkLine = lines[j];
          
          // Check for program ID validation patterns
          if ((checkLine.includes(".key()") && checkLine.includes("==")) ||
              (checkLine.includes("require!") && (checkLine.includes("program") || checkLine.includes("program_id"))) ||
              (checkLine.includes("Program<") && checkLine.includes("Account<")) ||
              (checkLine.includes("spl_token::ID") || checkLine.includes("system_program::ID"))) {
            hasProgramValidation = true;
            break;
          }
        }

        // Also check if Program<'info> is used with typed account (which validates automatically)
        let usesTypedProgram = false;
        for (let j = Math.max(0, i - 50); j < i; j++) {
          if (lines[j].includes("Program<") && lines[j].includes("Account<")) {
            usesTypedProgram = true;
            break;
          }
        }

        if (!hasProgramValidation && !usesTypedProgram) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "type-confusion");
          vulnerabilities.push({
            id: generateVulnerabilityId("external-program-validation", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Failure to Validate External Programs",
            description: pattern?.description || 
              `Program invocation at line ${i + 1} without program ID validation. An attacker could pass a malicious program.`,
            severity: Severity.CRITICAL,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Always validate program IDs before invocation. Use require!(program.key() == expected_program_id, ErrorCode::InvalidProgram) or use Anchor's typed Program accounts.",
            codeSnippet: lines.slice(Math.max(0, i - 5), i + 3).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}

/**
 * Detects missing account structure validation (discriminator checks)
 */
export class AccountStructureValidationDetector extends BaseDetector {
  name = "Missing Account Structure Validation";
  description = "Detects when account data is accessed without proper type validation or discriminator checks";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Look for direct data access without deserialization
      if (line.includes(".data.borrow()") || line.includes(".data.borrow_mut()")) {
        // Check if there's proper deserialization or type validation
        let hasValidation = false;
        
        // Look ahead for deserialization
        for (let j = i; j < Math.min(i + 10, lines.length); j++) {
          if (lines[j].includes("try_deserialize") ||
              lines[j].includes("Account::<") ||
              lines[j].includes("try_from") ||
              lines[j].includes("discriminator") ||
              lines[j].includes("Account::try_deserialize")) {
            hasValidation = true;
            break;
          }
        }

        // Also check if it's part of a typed Account<> which validates automatically
        let usesTypedAccount = false;
        for (let j = Math.max(0, i - 20); j < i; j++) {
          if (lines[j].includes("Account<") && !lines[j].includes("AccountInfo")) {
            usesTypedAccount = true;
            break;
          }
        }

        if (!hasValidation && !usesTypedAccount) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "account-data-mismatch");
          vulnerabilities.push({
            id: generateVulnerabilityId("account-structure-validation", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "Missing Account Structure Validation",
            description: pattern?.description || 
              `Account data accessed at line ${i + 1} without structure validation. An attacker could pass an account of the wrong type.`,
            severity: Severity.HIGH,
            category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Use Anchor's Account::<> type or manually deserialize with try_deserialize() to validate account structure and discriminator.",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 5).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }
}
