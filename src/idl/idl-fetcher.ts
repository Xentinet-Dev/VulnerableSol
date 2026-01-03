import * as fs from "fs/promises";
import * as path from "path";
import { fetchIdlFromRepo } from "./idl-from-repo.js";
import { fetchIdlFromChain } from "./idl-from-chain.js";
import { inferIdlFromBpf } from "./idl-from-bpf.js";
import { generateIdlFromSource } from "./idl-generator.js";

export class IdlFetcher {
  /**
   * Fetch IDL using all available strategies:
   * 0. Check vulnerability metadata for cached IDL (PHASE 1: Fastest path)
   * 1. Repo scan (target/idl) - if already built
   * 2. Generate IDL by building program - if source code available
   * 3. On-chain IDL PDA - if program deployed
   * 4. BPF binary inference - as last resort
   */
  static async getIdl(options: {
    programId?: string;
    repoPath?: string;
    bpfPath?: string;
    connection?: any;
    generateIfMissing?: boolean; // NEW: Generate IDL if not found
    vulnerabilityMetadata?: any; // PHASE 1: Check for cached IDL in vulnerability metadata
  }): Promise<{ idl: any; source: "repo" | "generated" | "chain" | "inferred-bpf" | "cached" } | null> {
    // 0 — PHASE 1 IMPROVEMENT: Check vulnerability metadata for cached IDL first (fastest)
    if (options.vulnerabilityMetadata) {
      if (options.vulnerabilityMetadata.cachedIdl) {
        console.log(`[+] Using cached IDL from scan phase (metadata)`);
        return { 
          idl: options.vulnerabilityMetadata.cachedIdl, 
          source: options.vulnerabilityMetadata.idlSource || "cached" 
        };
      }
    }
    
    // 1 — Try repo-based IDL (if already built)
    if (options.repoPath) {
      const repoIdl = await fetchIdlFromRepo(options.repoPath);
      if (repoIdl) return { idl: repoIdl, source: "repo" };
    }

    // 2 — Generate IDL by building program (if source code available)
    if (options.repoPath && (options.generateIfMissing !== false)) {
      try {
        console.log(`[*] Attempting to generate IDL from source: ${options.repoPath}`);
        console.log(`[*] Repository path exists: ${options.repoPath}`);
        
        // Validate path exists before attempting generation
        const fs = await import("fs/promises");
        const path = await import("path");
        try {
          const normalizedPath = path.isAbsolute(options.repoPath) 
            ? options.repoPath 
            : path.resolve(process.cwd(), options.repoPath);
          await fs.access(normalizedPath);
          console.log(`[+] Repository path is accessible: ${normalizedPath}`);
          
          const generated = await generateIdlFromSource({
            repoPath: normalizedPath,
            useDocker: true
          });
        
        if (generated.success && generated.idl) {
          console.log(`[+] IDL generated successfully from source`);
          if (generated.logs) {
            generated.logs.forEach(log => console.log(`    ${log}`));
          }
          return { idl: generated.idl, source: "generated" };
        } else {
          console.log(`[!] IDL generation failed: ${generated.error || 'Unknown error'}`);
          if (generated.logs) {
            generated.logs.forEach(log => console.log(`    ${log}`));
          }
        }
        } catch (pathError: any) {
          console.log(`[!] Repository path validation failed: ${pathError.message}`);
          console.log(`[!] Path: ${options.repoPath}`);
        }
      } catch (error: any) {
        // Continue to other strategies if generation fails
        console.log(`[!] IDL generation error: ${error.message || error}`);
        console.log(`[!] Continuing to other IDL fetch strategies...`);
      }
    } else {
      if (!options.repoPath) {
        console.log(`[!] Cannot generate IDL: No repository path provided`);
        console.log(`[!] Options received: repoPath=${options.repoPath}, generateIfMissing=${options.generateIfMissing}`);
      } else if (options.generateIfMissing === false) {
        console.log(`[!] IDL generation disabled (generateIfMissing=false)`);
      }
    }

    // 3 — Try chain-based IDL
    if (options.programId && options.connection) {
      try {
        const chainIdl = await fetchIdlFromChain(
          options.programId,
          options.connection
        );
        if (chainIdl) return { idl: chainIdl, source: "chain" };
      } catch {
        // fallback to BPF inference
      }
    }

    // 4 — Infer from BPF (last resort)
    if (options.bpfPath) {
      const inferred = await inferIdlFromBpf(options.bpfPath);
      if (inferred) return { idl: inferred, source: "inferred-bpf" };
    }

    return null;
  }
}

