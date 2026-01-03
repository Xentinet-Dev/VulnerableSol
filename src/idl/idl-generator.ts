/**
 * IDL Generator
 * 
 * Generates IDL by building Anchor programs when source code is available.
 * This ensures strategy-based exploits can always get IDL when we have the source.
 */

import * as fs from "fs/promises";
import * as path from "path";
import { DockerBuilder } from "../utils/docker-builder.js";

export interface IdlGenerationOptions {
  repoPath: string;
  programName?: string;
  useDocker?: boolean;
}

export interface IdlGenerationResult {
  success: boolean;
  idl?: any;
  idlPath?: string;
  error?: string;
  logs?: string[];
}

/**
 * Generate IDL by building the Anchor program
 * 
 * Strategy:
 * 1. Check if IDL already exists in target/idl/
 * 2. If not, build the program with Anchor
 * 3. Extract IDL from target/idl/*.json
 */
/**
 * Find Anchor workspace root by searching up from a given path
 */
async function findAnchorWorkspace(startPath: string): Promise<string | null> {
  let currentPath = path.resolve(startPath);
  const maxDepth = 10;

  for (let i = 0; i < maxDepth; i++) {
    const anchorToml = path.join(currentPath, "Anchor.toml");
    try {
      await fs.access(anchorToml);
      return currentPath;
    } catch {
      // Continue searching
    }

    const parent = path.dirname(currentPath);
    if (parent === currentPath) break; // Reached root
    currentPath = parent;
  }

  return null;
}

export async function generateIdlFromSource(
  options: IdlGenerationOptions
): Promise<IdlGenerationResult> {
  const logs: string[] = [];
  const { repoPath, programName, useDocker = true } = options;

  try {
    // Normalize path
    let normalizedPath = repoPath;
    if (!path.isAbsolute(repoPath)) {
      normalizedPath = path.resolve(process.cwd(), repoPath);
    }
    normalizedPath = path.normalize(normalizedPath);

    logs.push(`[*] Generating IDL from source: ${normalizedPath}`);
    console.log(`[*] IDL Generator: Starting for path: ${normalizedPath}`);

    // Step 1: Check if path exists
    try {
      await fs.access(normalizedPath);
      logs.push(`[+] Repository path exists`);
    } catch {
      logs.push(`[!] Repository path does not exist: ${normalizedPath}`);
      return {
        success: false,
        error: `Repository path does not exist: ${normalizedPath}`,
        logs
      };
    }

    // CRITICAL FIX: Find Anchor workspace root (where Anchor.toml is)
    // The provided path might be a program subdirectory, but we need the workspace root
    const workspaceRoot = await findAnchorWorkspace(normalizedPath);
    if (!workspaceRoot) {
      logs.push(`[!] No Anchor.toml found - cannot generate IDL`);
      logs.push(`[!] Searched from: ${normalizedPath}`);
      return {
        success: false,
        error: "Not an Anchor program (no Anchor.toml found)",
        logs
      };
    }

    if (workspaceRoot !== normalizedPath) {
      logs.push(`[+] Found Anchor workspace root: ${workspaceRoot}`);
      logs.push(`[+] Original path was subdirectory, using workspace root for build`);
    } else {
      logs.push(`[+] Path is already workspace root`);
    }

    // Use workspace root for all operations
    normalizedPath = workspaceRoot;

    // Step 2: Check if IDL already exists
    const idlDir = path.join(normalizedPath, "target/idl");
    try {
      await fs.access(idlDir);
      const files = await fs.readdir(idlDir);
      const idlFiles = files.filter(f => f.endsWith(".json"));
      
      if (idlFiles.length > 0) {
        const idlPath = path.join(idlDir, idlFiles[0]);
        const idlContent = await fs.readFile(idlPath, "utf8");
        const idl = JSON.parse(idlContent);
        
        logs.push(`[+] IDL already exists: ${idlFiles[0]}`);
        return {
          success: true,
          idl,
          idlPath,
          logs
        };
      }
    } catch {
      // IDL directory doesn't exist, need to build
      logs.push("[*] IDL not found, will build program");
    }

    // Step 3: Verify Anchor.toml exists (should always be true now)
    const anchorToml = path.join(normalizedPath, "Anchor.toml");
    try {
      await fs.access(anchorToml);
      logs.push("[+] Found Anchor.toml - this is an Anchor program");
    } catch {
      logs.push("[!] No Anchor.toml found at workspace root - this should not happen");
      return {
        success: false,
        error: "Not an Anchor program (no Anchor.toml found)",
        logs
      };
    }

    // Step 3: Build the program to generate IDL
    logs.push("[*] Building Anchor program to generate IDL...");
    
    // Extract program name from Anchor.toml or use provided name
    let detectedProgramName: string = programName || "program";
    try {
      const anchorTomlContent = await fs.readFile(anchorToml, "utf8");
      const nameMatch = anchorTomlContent.match(/\[programs\.localnet\]\s*(\w+)\s*=/);
      if (nameMatch) {
        detectedProgramName = nameMatch[1].trim();
        logs.push(`[+] Detected program name: ${detectedProgramName}`);
      }
    } catch {
      // Use default name if can't read Anchor.toml
    }
    
    if (useDocker) {
      // Use Docker for isolated build
      const dockerBuilder = new DockerBuilder();
      
      try {
        // Build the program (this will generate IDL in target/idl/)
        const buildResult = await dockerBuilder.buildProgram(normalizedPath, detectedProgramName);
        
        if (!buildResult.success) {
          logs.push(...buildResult.logs);
          logs.push(`[!] Build failed: ${buildResult.error}`);
          return {
            success: false,
            error: `Build failed: ${buildResult.error}`,
            logs
          };
        }

        logs.push("[+] Build successful, extracting IDL...");
        logs.push(...buildResult.logs);
        console.log(`[+] IDL Generator: Build successful, extracting IDL...`);
      } catch (error: any) {
        logs.push(`[!] Docker build error: ${error.message}`);
        return {
          success: false,
          error: `Docker build error: ${error.message}`,
          logs
        };
      }
    } else {
      // Native build using cargo build-sbf directly (bypasses Anchor's toolchain installer)
      logs.push("[*] Using native build with cargo build-sbf (bypasses Anchor toolchain)");
      
      const { exec } = await import("child_process");
      const { promisify } = await import("util");
      const execAsync = promisify(exec);

      try {
        // First, ensure program is built with cargo build-sbf
        logs.push("[*] Building program with cargo build-sbf --workspace...");
        await execAsync("cargo build-sbf --workspace --sbf-out-dir ./target/deploy", {
          cwd: normalizedPath,
          env: {
            ...process.env,
            RUSTUP_TOOLCHAIN: 'stable',
            CARGO_BUILD_SBF_USE_SYSTEM_RUST: 'true'
          }
        });
        logs.push("[+] Native build successful");
        
        // Generate IDL separately after build
        try {
          logs.push("[*] Generating IDL separately...");
          await execAsync("anchor idl build", {
            cwd: normalizedPath,
            env: { ...process.env }
          });
          logs.push("[+] IDL generated successfully");
        } catch (idlError: any) {
          logs.push(`[!] IDL generation failed (non-critical): ${idlError.message}`);
          // Continue - IDL generation failure is not critical
        }
      } catch (error: any) {
        logs.push(`[!] Native build failed: ${error.message}`);
        // Try to generate IDL anyway (might already exist from previous build)
        try {
          logs.push("[*] Attempting IDL generation despite build failure...");
          await execAsync("anchor idl build", {
            cwd: normalizedPath,
            env: { ...process.env }
          });
          logs.push("[+] IDL generated successfully");
        } catch (idlError: any) {
          logs.push(`[!] IDL generation also failed: ${idlError.message}`);
        }
        
        return {
          success: false,
          error: `Native build failed: ${error.message}`,
          logs
        };
      }
    }

    // Step 4: Extract IDL from target/idl/
    const idlDirAfterBuild = path.join(normalizedPath, "target/idl");
    try {
      await fs.access(idlDirAfterBuild);
      const files = await fs.readdir(idlDirAfterBuild);
      const idlFiles = files.filter(f => f.endsWith(".json"));
      
      if (idlFiles.length === 0) {
        logs.push("[!] Build succeeded but no IDL files found");
        return {
          success: false,
          error: "Build succeeded but no IDL files generated",
          logs
        };
      }

      // Use program name if provided, otherwise use first IDL file
      let idlFile = idlFiles[0];
      if (programName) {
        const namedIdl = idlFiles.find(f => f.includes(programName));
        if (namedIdl) {
          idlFile = namedIdl;
        }
      }

      const idlPath = path.join(idlDirAfterBuild, idlFile);
      const idlContent = await fs.readFile(idlPath, "utf8");
      const idl = JSON.parse(idlContent);

      logs.push(`[+] IDL generated successfully: ${idlFile}`);
      logs.push(`[+] Program name: ${idl.name || 'unknown'}`);
      logs.push(`[+] Instructions: ${idl.instructions?.length || 0}`);

      return {
        success: true,
        idl,
        idlPath,
        logs
      };
    } catch (error: any) {
      logs.push(`[!] Failed to read IDL after build: ${error.message}`);
      return {
        success: false,
        error: `Failed to read IDL: ${error.message}`,
        logs
      };
    }
  } catch (error: any) {
    logs.push(`[!] IDL generation error: ${error.message}`);
    return {
      success: false,
      error: error.message,
      logs
    };
  }
}
