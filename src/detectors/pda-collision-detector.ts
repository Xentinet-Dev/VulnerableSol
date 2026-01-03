import { BaseDetector } from "./base-detector.js";
import { Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { VULNERABILITY_REGISTRY } from "../knowledge-base/vulnerability-registry.js";
import { generateVulnerabilityId } from "../utils/id-generator.js";

/**
 * Detects PDA seed collision vulnerabilities
 * Identifies when all PDA seeds are user-controlled, allowing collision attacks
 */
export class PDACollisionDetector extends BaseDetector {
  name = "PDA Seed Collision";
  description = "Detects when all PDA seeds are user-controlled, allowing collision attacks";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".rs") || filePath.includes("anchor");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split("\n");

    // Pattern 1: All PDA seeds are user-controlled
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line.includes("find_program_address") || line.includes("create_program_address")) {
        // Extract seeds from the line and following lines
        let seedsContent = line;
        let j = i;
        while (j < Math.min(i + 5, lines.length) && !seedsContent.includes(')')) {
          seedsContent += lines[j];
          j++;
        }
        
        const seeds = this.extractSeeds(seedsContent);
        
        // Check if any seed is program-controlled
        const hasProgramSeed = seeds.some(seed => 
          seed.includes('"') || // String literal
          seed.includes("b\"") || // Byte literal
          seed.includes("b'") || // Byte literal
          seed.includes('SEED') || // Constant
          seed.includes('program_id') ||
          seed.includes('PROGRAM_ID')
        );
        
        if (!hasProgramSeed && seeds.length > 0) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "pda-seed-collision");
          vulnerabilities.push({
            id: generateVulnerabilityId("pda-collision", context?.filePath, i + 1, vulnerabilities.length),
            title: pattern?.name || "PDA Seed Collision - All Seeds User Controlled",
            description: pattern?.description || 
              "All PDA seeds are user-controlled, allowing collision attacks",
            severity: Severity.HIGH,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: pattern?.codeExamples.patched || 
              "Include at least one program-controlled seed like b\"vault\" or program_id",
            codeSnippet: lines.slice(Math.max(0, i - 2), Math.min(i + 5, lines.length)).join("\n"),
            metadata: {
              vulnerabilityType: 'pda-collision',
              userControlledSeeds: seeds
            },
            references: pattern?.references
          });
        }
      }

      // Pattern 2: Short or predictable seeds
      if (line.includes("find_program_address") && line.includes("&[")) {
        const seedMatch = line.match(/&\[\s*([^,\]]+)\s*\]/);
        if (seedMatch) {
          const seed = seedMatch[1].trim();
          // Check if seed is short (less than 10 chars when evaluated)
          if (seed.length < 10 && !seed.includes('as_ref()') && !seed.includes('program_id')) {
            const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "pda-seed-collision");
            vulnerabilities.push({
              id: generateVulnerabilityId("pda-short-seed", context?.filePath, i + 1, vulnerabilities.length),
              title: "PDA With Short Seed",
              description: "PDA using short seed increases collision probability",
              severity: Severity.MEDIUM,
              category: VulnerabilityCategory.ACCESS_CONTROL,
              location: {
                file: context?.filePath,
                line: i + 1
              },
              recommendation: "Use longer, more unique seeds",
              codeSnippet: lines.slice(Math.max(0, i - 2), i + 3).join("\n"),
              references: pattern?.references
            });
          }
        }
      }

      // Pattern 3: PDA without bump seed validation
      if (line.includes("find_program_address")) {
        // Check if bump is being used/validated
        const afterCode = lines.slice(i, Math.min(i + 10, lines.length)).join("\n");
        const hasBumpValidation = afterCode.includes('bump') || 
                                 afterCode.includes('canonical_bump') ||
                                 afterCode.includes('require!') && afterCode.includes('bump');
        
        // Check if bump is ignored
        const ignoresBump = line.includes(', _)') || line.includes(', _)');

        if (!hasBumpValidation && !ignoresBump) {
          const pattern = VULNERABILITY_REGISTRY.find(v => v.id === "pda-seed-collision");
          vulnerabilities.push({
            id: generateVulnerabilityId("pda-no-bump", context?.filePath, i + 1, vulnerabilities.length),
            title: "PDA Without Bump Seed Validation",
            description: "Not validating bump seed can lead to non-canonical PDA usage",
            severity: Severity.LOW,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: context?.filePath,
              line: i + 1
            },
            recommendation: "Store and validate canonical bump seed",
            codeSnippet: lines.slice(Math.max(0, i - 2), i + 5).join("\n"),
            references: pattern?.references
          });
        }
      }
    }

    return vulnerabilities;
  }

  private extractSeeds(seedsContent: string): string[] {
    // Extract individual seeds from the content
    const seedPattern = /([^,\[\]]+)/g;
    const matches = seedsContent.match(seedPattern);
    if (!matches) return [];
    
    return matches
      .map(s => s.trim())
      .filter(s => s && s !== '&' && s !== '[' && s !== ']' && s !== 'find_program_address');
  }
}
