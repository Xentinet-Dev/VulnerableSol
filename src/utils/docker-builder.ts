/**
 * Docker-based Builder for Anchor Programs
 * 
 * Uses Docker containers to build Anchor programs in an isolated environment
 * with correct Rust/Solana/Anchor versions, avoiding host system conflicts
 */

import { exec } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as fs from "fs/promises";
import { Connection, PublicKey, Keypair } from "@solana/web3.js";

const execAsync = promisify(exec);

export interface DockerBuildResult {
  success: boolean;
  programId?: string;
  programPath?: string;
  error?: string;
  logs: string[];
}

export class DockerBuilder {
  private containerName = "anchor-build-env";
  private validatorContainer = "solana-test-validator";

  /**
   * Check if Docker is available
   */
  async isDockerAvailable(): Promise<boolean> {
    try {
      await execAsync("docker --version");
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if containers are running
   */
  async areContainersRunning(): Promise<boolean> {
    try {
      const { stdout } = await execAsync(`docker ps --filter "name=${this.containerName}" --format "{{.Names}}"`);
      return stdout.trim().includes(this.containerName);
    } catch {
      return false;
    }
  }

  /**
   * Start Docker containers
   */
  async startContainers(): Promise<void> {
    const dockerComposePath = path.join(process.cwd(), "docker-compose.yml");
    const dockerComposeExists = await fs.access(dockerComposePath).then(() => true).catch(() => false);

    if (!dockerComposeExists) {
      throw new Error("docker-compose.yml not found. Run from scanner directory.");
    }

    console.log("[*] Starting Docker containers...");
    try {
      await execAsync(`docker-compose up -d`, { cwd: process.cwd() });
      console.log("[+] Docker containers started");
      
      // Wait for validator to be ready
      await new Promise(resolve => setTimeout(resolve, 5000));
    } catch (error: any) {
      throw new Error(`Failed to start Docker containers: ${error.message}`);
    }
  }

  /**
   * Build Anchor program in Docker container
   */
  async buildProgram(
    programPath: string,
    programName: string
  ): Promise<DockerBuildResult> {
    const logs: string[] = [];
    
    try {
      // Ensure containers are running
      if (!(await this.areContainersRunning())) {
        logs.push("[*] Starting Docker containers...");
        await this.startContainers();
      }

      // Find Anchor workspace root
      const workspaceRoot = await this.findAnchorWorkspace(programPath);
      if (!workspaceRoot) {
        return {
          success: false,
          error: "Anchor.toml not found",
          logs: [...logs, "[!] Could not find Anchor workspace"]
        };
      }

      logs.push(`[*] Building ${programName} in Docker container...`);
      logs.push(`[*] Workspace: ${workspaceRoot}`);

      // Verify container is responsive before building
      try {
        const testCmd = `docker exec ${this.containerName} echo "Container is responsive"`;
        await execAsync(testCmd, { timeout: 10000 }); // 10 second timeout for test
        logs.push(`[+] Container is responsive`);
      } catch (testError: any) {
        logs.push(`[!] Container health check failed: ${testError.message}`);
        logs.push(`[!] Container may be unresponsive or starting up`);
        return {
          success: false,
          error: `Container not responsive: ${testError.message}`,
          logs
        };
      }

      // Build in Docker container
      // Convert Windows path to container path (mounted at /workspace)
      // The scanner directory is mounted at /workspace in the container
      const scannerRoot = path.resolve(process.cwd()).replace(/\\/g, '/');
      const workspaceRootNormalized = workspaceRoot.replace(/\\/g, '/');
      
      // Calculate relative path from scanner root to workspace
      let relativePath = path.relative(scannerRoot, workspaceRootNormalized).replace(/\\/g, '/');
      
      // If paths are the same, use current directory
      let containerPath: string;
      if (!relativePath || relativePath === '.' || relativePath === '') {
        containerPath = '/workspace';
      } else {
        // Ensure path starts with /workspace
        containerPath = `/workspace/${relativePath.replace(/^\//, '')}`;
      }
      
      logs.push(`[*] Container path: ${containerPath}`);
      
      // Build using multiple simple docker exec commands instead of one complex command
      // This avoids the complex escaping issues that cause syntax errors
      const buildCommands = [
        // Step 1: Change to directory and clean up old toolchain files
        `docker exec ${this.containerName} bash -c "cd '${containerPath}' && echo '[*] Step 1/5: Cleaning up old toolchain files...' && rm -f rust-toolchain.toml rust-toolchain"`,

        // Step 2: Uninstall Solana toolchain
        `docker exec ${this.containerName} bash -c "cd '${containerPath}' && echo '[*] Step 2/5: Uninstalling Solana toolchain...' && rustup toolchain uninstall solana 2>/dev/null || true"`,

        // Step 3: Set stable Rust as default and verify
        `docker exec ${this.containerName} bash -c "cd '${containerPath}' && echo '[*] Step 3/5: Setting stable Rust as default and verifying...' && rustup default stable 2>&1 && rustc --version"`,

        // Step 4: Create rust-toolchain.toml with proper TOML syntax (always recreate to ensure correct format)
        // Use base64 encoding to avoid shell quoting issues completely
        // Base64 of: [toolchain]\nchannel = "stable"\ncomponents = ["rustfmt", "clippy"]\n
        `docker exec ${this.containerName} bash -c "cd '${containerPath}' && echo '[*] Step 4/5: Creating rust-toolchain.toml with proper syntax...' && rm -f rust-toolchain.toml rust-toolchain && echo 'W3Rvb2xjaGFpbl0KY2hhbm5lbCA9ICJzdGFibGUiCmNvbXBvbmVudHMgPSBbInJ1c3RmbXQiLCAiY2xpcHB5Il0=' | base64 -d > rust-toolchain.toml && echo '[+] rust-toolchain.toml created' && cat rust-toolchain.toml"`,

        // Step 5: Build the program using cargo build-sbf directly (bypasses Anchor's toolchain installer)
        // CRITICAL FIX: Use cargo build-sbf --workspace instead of anchor build
        // This completely bypasses Anchor's toolchain activation, solving the 1.75.0-dev issue
        // Also create .cargo/config.toml to force stable Rust at the Cargo level
        `docker exec ${this.containerName} bash -c "cd '${containerPath}' && echo '[*] Step 5/5: Building program with cargo build-sbf (first build: 10-15 min, cached: 2-5 min)...' && echo '[+] Removing Solana toolchain...' && rustup toolchain uninstall solana 2>/dev/null || true && echo '[+] Setting stable toolchain...' && rustup default stable && echo '[+] Creating .cargo/config.toml to force stable Rust...' && mkdir -p .cargo && echo '[build]' > .cargo/config.toml && echo 'rustc = \"rustc\"' >> .cargo/config.toml && echo '[+] Verifying active toolchain...' && rustup show active-toolchain && rustc --version && echo '[+] Building with cargo build-sbf --workspace...' && export RUSTUP_TOOLCHAIN=stable && export CARGO_BUILD_SBF_USE_SYSTEM_RUST=true && unset RUSTUP_TOOLCHAIN_SOLANA && cargo build-sbf --workspace --sbf-out-dir ./target/deploy 2>&1 && echo '[+] Build complete, generating IDL...' && anchor idl build 2>/dev/null || echo '[!] IDL generation skipped (non-critical)'"`
      ];
      
      // First builds can take 10-15 minutes (downloading dependencies, compiling Rust)
      // Subsequent builds are faster (2-5 minutes) due to caching
      const BUILD_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes for first builds
      logs.push(`[*] Executing build command (timeout: 15 minutes for first build, 2-5 minutes for cached builds)...`);
      console.log(`[*] Build started at ${new Date().toISOString()}`);
      console.log(`[*] Timeout set to 15 minutes (first builds can take 10-15 minutes due to dependency downloads)`);
      
      try {
        // Execute build commands sequentially with overall timeout
        const startTime = Date.now();
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error("Build timeout: Command exceeded 15 minute limit")), BUILD_TIMEOUT_MS);
        });

        // Execute commands sequentially
        let allStdout = "";
        let allStderr = "";

        for (let i = 0; i < buildCommands.length; i++) {
          const cmd = buildCommands[i];
          console.log(`[*] Executing step ${i + 1}/${buildCommands.length}...`);

          // Check if we've exceeded timeout
          if (Date.now() - startTime > BUILD_TIMEOUT_MS) {
            throw new Error("Build timeout: Command exceeded 15 minute limit");
          }

          const execPromise = execAsync(cmd, {
            cwd: process.cwd(),
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer
          });

          const { stdout, stderr } = await Promise.race([execPromise, timeoutPromise]) as any;
          allStdout += stdout || "";
          allStderr += stderr || "";
        }

        const { stdout, stderr } = { stdout: allStdout, stderr: allStderr };

        console.log(`[+] Build completed at ${new Date().toISOString()}`);
        
        // Log output in real-time chunks
        const stdoutLines = stdout.split("\n").filter((line: string) => line.trim());
        const stderrLines = stderr ? stderr.split("\n").filter((line: string) => line.trim()) : [];
        
        // Log important progress indicators
        stdoutLines.forEach((line: string) => {
          if (line.includes("Step") || line.includes("Building") || line.includes("Compiling") || line.includes("Finished") || line.includes("error") || line.includes("warning")) {
            console.log(`[Docker] ${line}`);
          }
        });
        
        logs.push(...stdoutLines);
        if (stderrLines.length > 0) {
          logs.push(...stderrLines);
        }

        // Extract program ID from build output or keypair file
        const programId = await this.extractProgramId(workspaceRoot, programName);

        return {
          success: true,
          programId,
          programPath: path.join(workspaceRoot, "target", "deploy", `${programName}.so`),
          logs
        };
      } catch (buildError: any) {
        console.log(`[!] Build failed at ${new Date().toISOString()}`);
        console.log(`[!] Error: ${buildError.message}`);
        
        logs.push(`[!] Build failed: ${buildError.message}`);
        
        // Check if it was a timeout
        if (buildError.message.includes("timeout") || buildError.message.includes("exceeded")) {
          logs.push(`[!] Build timed out after 15 minutes`);
          logs.push(`[!] This usually means the build is taking longer than expected`);
          logs.push(`[!] Possible causes:`);
          logs.push(`[!]   - Very large program with many dependencies`);
          logs.push(`[!]   - Slow network (downloading dependencies)`);
          logs.push(`[!]   - Container resource constraints (CPU/memory)`);
          logs.push(`[!]   - Docker build cache issues`);
          logs.push(`[!] Recommendation:`);
          logs.push(`[!]   - Check Docker container logs: docker logs anchor-build-env`);
          logs.push(`[!]   - Check if build is still running: docker exec anchor-build-env ps aux`);
          logs.push(`[!]   - Try native build (may have version conflicts)`);
          logs.push(`[!]   - Increase timeout if this is a very large program`);
        }
        
        // Capture full error output for debugging
        const allOutput: string[] = [];
        
        if (buildError.stdout) {
          const stdoutLines = buildError.stdout.split("\n").filter((line: string) => line.trim());
          allOutput.push(...stdoutLines);
          // Log last few lines to console
          if (stdoutLines.length > 0) {
            console.log(`[!] Last build output lines:`);
            stdoutLines.slice(-10).forEach((line: string) => console.log(`    ${line}`));
          }
        }
        if (buildError.stderr) {
          const stderrLines = buildError.stderr.split("\n").filter((line: string) => line.trim());
          allOutput.push(...stderrLines);
          // Log errors to console
          if (stderrLines.length > 0) {
            console.log(`[!] Build errors:`);
            stderrLines.slice(-10).forEach((line: string) => console.log(`    ${line}`));
          }
        }
        
        // Show error output (last 30 lines for better debugging)
        if (allOutput.length > 0) {
          if (allOutput.length > 30) {
            logs.push(`[!] ... (showing last 30 lines of ${allOutput.length} total lines)`);
            logs.push(...allOutput.slice(-30));
          } else {
            logs.push(...allOutput);
          }
        } else {
          // If no output captured, try to get it from the error message
          logs.push(`[!] Error details: ${buildError.message}`);
        }

        return {
          success: false,
          error: buildError.message,
          logs
        };
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        logs: [...logs, `[!] Error: ${error.message}`]
      };
    }
  }

  /**
   * Deploy program to validator using native solana CLI (from host, not Docker)
   * This ensures programs are properly loaded into validator runtime
   */
  async deployProgram(
    programPath: string,
    programName: string
  ): Promise<DockerBuildResult> {
    const buildResult = await this.buildProgram(programPath, programName);
    
    if (!buildResult.success || !buildResult.programPath) {
      return buildResult;
    }

    try {
      const workspaceRoot = await this.findAnchorWorkspace(programPath);
      if (!workspaceRoot) {
        return {
          ...buildResult,
          success: false,
          error: "Could not find workspace for deployment"
        };
      }

      buildResult.logs.push(`[*] Deploying ${programName} to validator using native solana CLI...`);
      buildResult.logs.push(`[*] This ensures programs are properly loaded into validator runtime`);

      // Pre-flight check: Verify solana CLI is available
      try {
        await execAsync("solana --version", { timeout: 5000 });
        buildResult.logs.push(`[+] Solana CLI detected and available`);
      } catch (error: any) {
        return {
          ...buildResult,
          success: false,
          error: `Solana CLI not found. Please install Solana CLI tools: https://docs.solana.com/cli/install-solana-cli-tools\n\nRequired for program deployment.`,
          logs: [...buildResult.logs, 
            `[!] ERROR: Solana CLI not found on host system`,
            `[!] Installation: https://docs.solana.com/cli/install-solana-cli-tools`,
            `[!] After installation, ensure 'solana' is in your PATH`
          ]
        };
      }

      // Find the .so file and keypair file (they should be in target/deploy/)
      const soFile = path.join(workspaceRoot, "target", "deploy", `${programName}.so`);
      const keypairFile = path.join(workspaceRoot, "target", "deploy", `${programName}-keypair.json`);

      // Verify files exist
      try {
        await fs.access(soFile);
        await fs.access(keypairFile);
      } catch (error: any) {
        return {
          ...buildResult,
          success: false,
          error: `Deployment artifacts not found. Expected:\n  ${soFile}\n  ${keypairFile}\n\nBuild may have failed.`,
          logs: [...buildResult.logs, `[!] Error: ${error.message}`]
        };
      }

      // Read program ID from keypair
      let programId: string;
      try {
        const keypairData = JSON.parse(await fs.readFile(keypairFile, "utf8"));
        const keypair = Keypair.fromSecretKey(Uint8Array.from(keypairData));
        programId = keypair.publicKey.toBase58();
        buildResult.programId = programId;
        buildResult.logs.push(`[*] Program ID: ${programId}`);
      } catch (error: any) {
        return {
          ...buildResult,
          success: false,
          error: `Failed to read program keypair: ${error.message}`,
          logs: [...buildResult.logs, `[!] Error reading keypair: ${error.message}`]
        };
      }

      // Deploy using native solana CLI from host (not Docker)
      // This ensures programs are properly loaded into validator runtime
      buildResult.logs.push(`[*] Deploying from host using: solana program deploy`);
      buildResult.logs.push(`[*] This method ensures programs are properly loaded into validator runtime`);
      
      const deployCommand = `solana program deploy "${soFile}" --program-id "${keypairFile}" --url http://localhost:8899`;
      
      // Try deployment with retry logic (up to 3 attempts)
      let deploymentSucceeded = false;
      const maxDeployAttempts = 3;
      
      for (let deployAttempt = 1; deployAttempt <= maxDeployAttempts; deployAttempt++) {
        try {
          if (deployAttempt > 1) {
            buildResult.logs.push(`[*] Retry attempt ${deployAttempt}/${maxDeployAttempts}...`);
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds between retries
          }

          const { stdout, stderr } = await execAsync(deployCommand, {
            cwd: workspaceRoot,
            maxBuffer: 10 * 1024 * 1024,
            env: {
              ...process.env,
              SOLANA_URL: "http://localhost:8899"
            }
          });

          buildResult.logs.push(...stdout.split("\n").filter((line: string) => line.trim()));
          if (stderr) {
            buildResult.logs.push(...stderr.split("\n").filter((line: string) => line.trim()));
          }

          buildResult.logs.push(`[+] Deployment command completed successfully`);
          deploymentSucceeded = true;
          break; // Success, exit retry loop
        } catch (deployError: any) {
          // Check if it's a "program already deployed" error (that's okay)
          if (deployError.stdout && (
            deployError.stdout.includes("Program deployed") ||
            deployError.stdout.includes("already deployed")
          )) {
            buildResult.logs.push(`[!] Program already deployed (this is okay, continuing...)`);
            deploymentSucceeded = true;
            break;
          } else {
            buildResult.logs.push(`[!] Deployment attempt ${deployAttempt}/${maxDeployAttempts} failed: ${deployError.message}`);
            if (deployError.stdout) {
              const stdoutLines = deployError.stdout.split("\n").filter((line: string) => line.trim());
              if (stdoutLines.length > 0) {
                buildResult.logs.push(`[!] Deployment output:`, ...stdoutLines.slice(-5)); // Last 5 lines
              }
            }
            if (deployError.stderr) {
              const stderrLines = deployError.stderr.split("\n").filter((line: string) => line.trim());
              if (stderrLines.length > 0) {
                buildResult.logs.push(`[!] Deployment errors:`, ...stderrLines.slice(-5)); // Last 5 lines
              }
            }
            
            // If this was the last attempt, we'll still try to verify (maybe it worked despite error)
            if (deployAttempt === maxDeployAttempts) {
              buildResult.logs.push(`[!] All deployment attempts failed, but will verify if program is loaded...`);
            }
          }
        }
      }
      
      if (!deploymentSucceeded) {
        buildResult.logs.push(`[!] WARNING: Deployment command failed after ${maxDeployAttempts} attempts`);
        buildResult.logs.push(`[!] Will still attempt to verify if program is loaded (may have succeeded despite errors)`);
      }

      // Verify program is actually deployed and loaded in validator (with retry)
      buildResult.logs.push(`[*] Verifying program is loaded in validator runtime...`);
      const verificationResult = await this.waitForProgramLoaded(programId, 10, 1000);
      
      if (!verificationResult.isDeployed) {
        return {
          ...buildResult,
          success: false,
          error: `Program deployment failed: Program not found in validator after deployment`,
          logs: [...buildResult.logs, 
            `[!] ERROR: Program ${programId.slice(0, 16)}... not found in validator`,
            `[!] This means the program was not successfully loaded into the validator runtime`,
            `[!] Possible causes:`,
            `[!]   1. Validator is not running or not accessible`,
            `[!]   2. Program deployment command failed silently`,
            `[!]   3. Network connectivity issues between host and validator`
          ]
        };
      } else if (!verificationResult.isExecutable) {
        return {
          ...buildResult,
          success: false,
          error: `Program deployment incomplete: Program exists but is not executable`,
          logs: [...buildResult.logs,
            `[!] ERROR: Program ${programId.slice(0, 16)}... exists but is not marked as executable`,
            `[!] This means the program account was created but not properly loaded`,
            `[!] Try redeploying the program or restarting the validator`
          ]
        };
      } else {
        buildResult.logs.push(`[+] Program verified: deployed and executable in validator runtime`);
        buildResult.logs.push(`[+] Program ID: ${programId}`);
        buildResult.logs.push(`[+] Program is ready for transaction execution`);
      }

      return {
        ...buildResult,
        success: true,
        programId
      };
    } catch (error: any) {
      return {
        ...buildResult,
        success: false,
        error: `Deployment failed: ${error.message}`,
        logs: [...buildResult.logs, `[!] Deployment error: ${error.message}`, `[!] Stack: ${error.stack}`]
      };
    }
  }

  /**
   * Find Anchor workspace root
   */
  private async findAnchorWorkspace(startPath: string): Promise<string | null> {
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

  /**
   * Extract program ID from keypair file
   */
  private async extractProgramId(workspaceRoot: string, programName: string): Promise<string | undefined> {
    try {
      // Try to read from keypair file
      const keypairPath = path.join(workspaceRoot, "target", "deploy", `${programName}-keypair.json`);
      const keypairData = await fs.readFile(keypairPath, "utf8");
      const keypairArray = JSON.parse(keypairData);
      
      // Convert keypair array to Keypair object and extract public key
      if (Array.isArray(keypairArray) && keypairArray.length >= 32) {
        const keypair = Keypair.fromSecretKey(Uint8Array.from(keypairArray));
        return keypair.publicKey.toBase58();
      }
    } catch (error: any) {
      // Keypair file not found or invalid - this is okay, we'll try to get it during deployment
      console.log(`[!] Could not extract program ID from keypair: ${error.message}`);
    }

    return undefined;
  }

  /**
   * Wait for program to be loaded in validator runtime (with retry logic)
   * This ensures programs are actually available for execution before proceeding
   */
  private async waitForProgramLoaded(
    programId: string,
    maxAttempts: number = 10,
    delayMs: number = 1000
  ): Promise<{ isDeployed: boolean; isExecutable: boolean }> {
    const connection = new Connection("http://localhost:8899", "confirmed");
    const programPublicKey = new PublicKey(programId);

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const accountInfo = await connection.getAccountInfo(programPublicKey);
        
        if (accountInfo) {
          const isExecutable = accountInfo.executable === true;
          
          if (isExecutable) {
            // Program is loaded and executable - success!
            return { isDeployed: true, isExecutable: true };
          } else {
            // Program account exists but not executable yet - keep waiting
            if (attempt < maxAttempts) {
              await new Promise(resolve => setTimeout(resolve, delayMs));
              continue;
            } else {
              // Timeout - program exists but not executable
              return { isDeployed: true, isExecutable: false };
            }
          }
        } else {
          // Program account doesn't exist yet - keep waiting
          if (attempt < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, delayMs));
            continue;
          } else {
            // Timeout - program not found
            return { isDeployed: false, isExecutable: false };
          }
        }
      } catch (error: any) {
        // Error checking account - might be network issue, keep retrying
        if (attempt < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
          continue;
        } else {
          // Final attempt failed
          return { isDeployed: false, isExecutable: false };
        }
      }
    }

    // Should never reach here, but just in case
    return { isDeployed: false, isExecutable: false };
  }

  /**
   * Get validator URL (from Docker network)
   */
  getValidatorUrl(): string {
    return "http://localhost:8899"; // Exposed port
  }

  /**
   * Stop Docker containers
   */
  async stopContainers(): Promise<void> {
    try {
      await execAsync("docker-compose down", { cwd: process.cwd() });
      console.log("[+] Docker containers stopped");
    } catch (error: any) {
      console.log(`[!] Error stopping containers: ${error.message}`);
    }
  }
}

