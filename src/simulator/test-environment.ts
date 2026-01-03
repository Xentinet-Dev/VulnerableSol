/**
 * Test Environment Manager
 * 
 * Sets up isolated Solana test environments for exploit simulation
 */

import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs/promises";
import * as path from "path";
import { isRunningAsAdmin, getAdminRequirementMessage } from "../utils/admin-check.js";
import { DockerBuilder } from "../utils/docker-builder.js";

const execAsync = promisify(exec);

export interface TestEnvironment {
  validatorUrl: string;
  connection: Connection;
  provider: anchor.AnchorProvider;
  wallet: anchor.Wallet;
  deployedPrograms: Map<string, PublicKey>;
  cleanup: () => Promise<void>;
}

/**
 * Manages test environments for exploit simulation
 */
export class TestEnvironmentManager {
  private environments: Map<string, TestEnvironment> = new Map();
  private validatorProcesses: Map<string, any> = new Map();
  private dockerBuilder: DockerBuilder | null = null;
  private useDocker: boolean = false;

  /**
   * Initialize Docker builder if available
   */
  private async initDocker(): Promise<boolean> {
    if (this.dockerBuilder) {
      return this.useDocker;
    }

    try {
      this.dockerBuilder = new DockerBuilder();
      const dockerAvailable = await this.dockerBuilder.isDockerAvailable();
      
      if (dockerAvailable) {
        console.log("[*] Docker detected - will use containerized builds");
        this.useDocker = true;
        return true;
      }
    } catch (error) {
      console.log("[!] Docker not available, using native builds");
    }

    this.useDocker = false;
    return false;
  }

  /**
   * Create a new test environment
   * @param envId - Environment identifier
   * @param userWalletAddress - Optional: Use user's wallet address instead of generating one
   * @param cluster - Optional: Cluster type ('localnet', 'devnet', 'testnet', 'mainnet'). Default: 'localnet'
   */
  async createEnvironment(
    envId: string, 
    userWalletAddress?: string,
    cluster: 'localnet' | 'devnet' | 'testnet' | 'mainnet' = 'localnet'
  ): Promise<TestEnvironment> {
    // Determine validator URL based on cluster
    let validatorUrl: string;
    let requiresValidator = false;
    
    switch (cluster) {
      case 'localnet':
        validatorUrl = "http://localhost:8899";
        requiresValidator = true;
        break;
      case 'devnet':
        validatorUrl = "https://api.devnet.solana.com";
        requiresValidator = false;
        break;
      case 'testnet':
        validatorUrl = "https://api.testnet.solana.com";
        requiresValidator = false;
        break;
      case 'mainnet':
        validatorUrl = "https://api.mainnet-beta.solana.com";
        requiresValidator = false;
        console.warn("[!] WARNING: Using mainnet for testing is dangerous and not recommended!");
        break;
      default:
        validatorUrl = "http://localhost:8899";
        requiresValidator = true;
    }
    
    console.log(`[*] Creating test environment on ${cluster} cluster: ${validatorUrl}`);
    
    // Start local validator only if using localnet
    if (requiresValidator) {
      await this.startValidator(envId);
    } else {
      console.log(`[*] Using remote ${cluster} cluster - no local validator needed`);
      console.log(`[!] NOTE: Programs must be deployed to ${cluster} before testing`);
      console.log(`[!] NOTE: You'll need SOL on ${cluster} for transaction fees`);
    }
    
    // Create connection
    const connection = new Connection(validatorUrl, "confirmed");
    
    // Use user's wallet if provided, otherwise generate one
    let wallet: Keypair;
    if (userWalletAddress) {
      // For user wallet, we can't sign transactions without the private key
      // So we'll still generate a wallet but note the user's address for reference
      wallet = Keypair.generate();
      console.log(`[!] User wallet provided: ${userWalletAddress}`);
      console.log(`[!] Using generated wallet for signing: ${wallet.publicKey.toBase58()}`);
      console.log(`[!] Note: To use your wallet, you need to provide the keypair file`);
    } else {
      wallet = Keypair.generate();
    }
    
    const provider = new anchor.AnchorProvider(
      connection,
      new anchor.Wallet(wallet),
      { commitment: "confirmed" }
    );
    
    // Wait for validator to be fully ready (only for localnet)
    if (requiresValidator) {
      await this.waitForValidatorReady(connection);
    } else {
      // For remote clusters, just verify connection
      try {
        const version = await connection.getVersion();
        console.log(`[+] Connected to ${cluster} cluster (version: ${version['solana-core']})`);
      } catch (error: any) {
        console.log(`[!] Failed to connect to ${cluster}: ${error.message}`);
        throw new Error(`Cannot connect to ${cluster} cluster. Check your internet connection.`);
      }
    }
    
    // Funding: Different approach for localnet vs remote clusters
    if (requiresValidator) {
      // Localnet: Use alternative funding (airdrop doesn't work on Windows validator)
      console.log("[*] Funding wallet using alternative method (airdrop disabled)...");
      try {
        await this.fundFromValidatorDefault(connection, wallet.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL);
        console.log("[+] Wallet funded successfully");
      } catch (error: any) {
        console.log(`[!] Funding failed: ${error.message}`);
        console.log("[!] Continuing without funding - some tests may fail");
      }
    } else {
      // Remote clusters: Try airdrop (works on devnet/testnet)
      if (cluster === 'devnet' || cluster === 'testnet') {
        console.log(`[*] Requesting airdrop from ${cluster}...`);
        try {
          await this.requestAirdropWithRetry(connection, wallet.publicKey, 2 * anchor.web3.LAMPORTS_PER_SOL);
          console.log(`[+] Wallet funded successfully from ${cluster}`);
        } catch (error: any) {
          console.log(`[!] Airdrop failed: ${error.message}`);
          console.log(`[!] You may need to manually fund the wallet: ${wallet.publicKey.toBase58()}`);
          console.log(`[!] Get SOL from: https://faucet.solana.com (devnet) or https://faucet.testnet.solana.com (testnet)`);
        }
      } else {
        // Mainnet: No automatic funding
        console.log(`[!] WARNING: No automatic funding on mainnet`);
        console.log(`[!] Wallet address: ${wallet.publicKey.toBase58()}`);
        console.log(`[!] You must manually fund this wallet before testing`);
      }
    }
    
    const environment: TestEnvironment = {
      validatorUrl,
      connection,
      provider,
      wallet: new anchor.Wallet(wallet),
      deployedPrograms: new Map(),
      cleanup: async () => {
        await this.cleanupEnvironment(envId);
      }
    };
    
    this.environments.set(envId, environment);
    return environment;
  }

  /**
   * Wait for validator to be fully ready (processing blocks)
   */
  private async waitForValidatorReady(connection: Connection, maxWait: number = 10000): Promise<void> {
    const startTime = Date.now();
    while (Date.now() - startTime < maxWait) {
      try {
        const slot = await connection.getSlot();
        if (slot > 0) {
          console.log("[*] Validator is ready (slot:", slot, ")");
          // Wait a bit more for RPC to be fully initialized
          await new Promise(resolve => setTimeout(resolve, 1000));
          return;
        }
      } catch (error) {
        // Validator not ready yet
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    console.log("[!] Validator readiness timeout - proceeding anyway");
  }

  /**
   * Request airdrop with retry logic
   */
  private async requestAirdropWithRetry(
    connection: Connection,
    publicKey: PublicKey,
    lamports: number,
    maxRetries: number = 5
  ): Promise<void> {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const signature = await connection.requestAirdrop(publicKey, lamports);
        
        // Wait for confirmation
        await connection.confirmTransaction(signature, "confirmed");
        
        // Verify balance
        const balance = await connection.getBalance(publicKey);
        if (balance >= lamports) {
          console.log(`[+] Airdrop successful: ${lamports / anchor.web3.LAMPORTS_PER_SOL} SOL`);
          return;
        }
      } catch (error: any) {
        if (attempt === maxRetries) {
          console.log(`[!] Airdrop failed after ${maxRetries} attempts: ${error.message}`);
          console.log("[*] Trying alternative funding method...");
          
          // Fallback: Try to fund from validator's default keypair
          try {
            await this.fundFromValidatorDefault(connection, publicKey, lamports);
            return;
          } catch (fundError: any) {
            console.log(`[!] Alternative funding also failed: ${fundError.message}`);
            console.log("[!] Continuing without funding - some tests may fail");
            console.log("[💡] Tip: Restart validator with --reset to enable airdrops");
            return;
          }
        }
        console.log(`[!] Airdrop attempt ${attempt} failed, retrying... (${error.message})`);
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt)); // Exponential backoff
      }
    }
  }

  /**
   * Alternative funding method: Transfer from validator's default keypair
   */
  private async fundFromValidatorDefault(
    connection: Connection,
    targetPublicKey: PublicKey,
    lamports: number
  ): Promise<void> {
    const path = await import("path");
    const fs = await import("fs/promises");
    
    // Method 1: Try using validator keypair file (for Docker-mounted volume)
    try {
      // Try multiple possible locations for validator keypair
      const possiblePaths = [
        path.join(process.cwd(), "test-ledger", "validator-keypair.json"),
        path.join(process.cwd(), "..", "test-ledger", "validator-keypair.json"),
        path.join(process.env.USERPROFILE || process.env.HOME || "", "test-ledger", "validator-keypair.json"),
      ];
      
      let keypairPath: string | null = null;
      for (const testPath of possiblePaths) {
        try {
          await fs.access(testPath);
          keypairPath = testPath;
          console.log(`[+] Found validator keypair at: ${keypairPath}`);
          break;
        } catch {
          // Try next path
        }
      }
      
      if (keypairPath) {
        const keypairData = await fs.readFile(keypairPath, "utf-8");
        const keypairBytes = JSON.parse(keypairData);
        const fundedKeypair = Keypair.fromSecretKey(Uint8Array.from(keypairBytes));
        
        // Check balance
        const balance = await connection.getBalance(fundedKeypair.publicKey);
        console.log(`[+] Validator keypair balance: ${balance / anchor.web3.LAMPORTS_PER_SOL} SOL`);
        
        if (balance < lamports) {
          throw new Error(`Insufficient balance in validator keypair: ${balance} < ${lamports}`);
        }
        
        // Transfer funds
        const transaction = new anchor.web3.Transaction().add(
          SystemProgram.transfer({
            fromPubkey: fundedKeypair.publicKey,
            toPubkey: targetPublicKey,
            lamports: lamports
          })
        );
        
        const signature = await anchor.web3.sendAndConfirmTransaction(
          connection,
          transaction,
          [fundedKeypair],
          { commitment: "confirmed" }
        );
        
        // Verify
        const targetBalance = await connection.getBalance(targetPublicKey);
        if (targetBalance >= lamports) {
          console.log(`[+] Alternative funding successful: ${lamports / anchor.web3.LAMPORTS_PER_SOL} SOL transferred`);
          console.log(`[+] Transaction signature: ${signature}`);
          return;
        }
      }
    } catch (keypairError: any) {
      console.log(`[!] Keypair funding failed: ${keypairError.message}`);
      // Fall through to Method 2
    }
    
    // Method 2: Try using solana airdrop via Docker exec (if validator is in Docker)
    try {
      console.log("[*] Attempting airdrop via Docker...");
      const { exec } = await import("child_process");
      const { promisify } = await import("util");
      const execAsync = promisify(exec);
      
      // Check if validator is in Docker
      const dockerCheck = await execAsync("docker ps --filter name=solana-test-validator --format {{.Names}}").catch(() => ({ stdout: "" }));
      if (dockerCheck.stdout.includes("solana-test-validator")) {
        const solAmount = lamports / anchor.web3.LAMPORTS_PER_SOL;
        const airdropCmd = `docker exec solana-test-validator solana airdrop ${solAmount} ${targetPublicKey.toBase58()} --url http://localhost:8899`;
        
        console.log(`[*] Running: ${airdropCmd}`);
        const result = await execAsync(airdropCmd);
        console.log(`[+] Docker airdrop output: ${result.stdout}`);
        
        // Wait a moment for transaction to confirm
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Verify
        const targetBalance = await connection.getBalance(targetPublicKey);
        if (targetBalance >= lamports) {
          console.log(`[+] Docker airdrop successful: ${lamports / anchor.web3.LAMPORTS_PER_SOL} SOL transferred`);
          return;
        }
      }
    } catch (dockerError: any) {
      console.log(`[!] Docker airdrop failed: ${dockerError.message}`);
      // Fall through to final error
    }
    
    // Method 3: Try direct airdrop request (sometimes works on test validator)
    try {
      console.log("[*] Attempting direct airdrop request...");
      const signature = await connection.requestAirdrop(targetPublicKey, lamports);
      await connection.confirmTransaction(signature, "confirmed");
      
      // Verify
      const targetBalance = await connection.getBalance(targetPublicKey);
      if (targetBalance >= lamports) {
        console.log(`[+] Direct airdrop successful: ${lamports / anchor.web3.LAMPORTS_PER_SOL} SOL transferred`);
        return;
      }
    } catch (airdropError: any) {
      console.log(`[!] Direct airdrop failed: ${airdropError.message}`);
    }
    
    // All methods failed
    throw new Error(`All funding methods failed. Could not fund wallet ${targetPublicKey.toBase58()} with ${lamports / anchor.web3.LAMPORTS_PER_SOL} SOL`);
  }

  /**
   * Fund a wallet from validator (public method for use in exploit tests)
   */
  async fundWalletFromValidator(
    connection: Connection,
    targetPublicKey: PublicKey,
    lamports: number
  ): Promise<void> {
    await this.fundFromValidatorDefault(connection, targetPublicKey, lamports);
  }

  /**
   * Start local Solana validator
   */
  private async startValidator(envId: string): Promise<void> {
    // Check if validator is already running
    try {
      const connection = new Connection("http://localhost:8899", "confirmed");
      await connection.getVersion();
      console.log("[*] Validator already running");
      return;
    } catch (error) {
      // Validator not running, try to start it
      console.log("[*] Starting local Solana validator...");
      
      // Check admin privileges on Windows
      const isAdmin = await isRunningAsAdmin();
      if (process.platform === "win32" && !isAdmin) {
        console.log("[!] ⚠️  ADMINISTRATOR PRIVILEGES REQUIRED");
        console.log("[!] The Solana test validator requires admin privileges on Windows.");
        console.log("[!]");
        console.log("[!] OPTIONS:");
        console.log("[!] 1. Run Cursor as Administrator (Recommended)");
        console.log("[!]    - Right-click Cursor → 'Run as administrator'");
        console.log("[!]    - All processes will inherit admin privileges");
        console.log("[!]");
        console.log("[!] 2. Start Validator Manually");
        console.log("[!]    - Run: START_VALIDATOR_AS_ADMIN.ps1");
        console.log("[!]    - Or: solana-test-validator --reset (in admin PowerShell)");
        console.log("[!]");
        console.log("[!] Falling back to static analysis mode (no real exploit simulation)");
        throw new Error("Admin privileges required to start validator");
      }
      
      try {
        // Check if solana-test-validator is available
        await execAsync("solana-test-validator --version");
        
        // Start validator in background (removed --reset to preserve deployed programs)
        const validatorProcess = exec("solana-test-validator --quiet", {
          cwd: process.cwd()
        });
        
        // Redirect output to prevent cluttering console
        validatorProcess.stdout?.on('data', () => {});
        validatorProcess.stderr?.on('data', (data: Buffer) => {
          // Check for privilege errors
          const errorStr = data.toString();
          if (errorStr.includes("1314") || errorStr.includes("privilege")) {
            console.log("[!] ⚠️  PRIVILEGE ERROR DETECTED");
            console.log("[!] The validator requires administrator privileges.");
            console.log(getAdminRequirementMessage());
          }
        });
        
        this.validatorProcesses.set(envId, validatorProcess);
        
        // Wait for validator to be ready (max 30 seconds)
        const maxWait = 30000;
        const startTime = Date.now();
        while (Date.now() - startTime < maxWait) {
          try {
            const testConnection = new Connection("http://localhost:8899", "confirmed");
            await testConnection.getVersion();
            console.log("[+] Validator started successfully");
            if (isAdmin) {
              console.log("[+] Running with administrator privileges");
            }
            return;
          } catch (e) {
            await new Promise(resolve => setTimeout(resolve, 500));
          }
        }
        
        throw new Error("Validator failed to start within timeout");
      } catch (error: any) {
        console.log("[!] Could not start validator automatically:");
        console.log(`    ${error.message}`);
        if (error.message.includes("1314") || error.message.includes("privilege")) {
          console.log(getAdminRequirementMessage());
        } else {
          console.log("[!] Please start manually: solana-test-validator");
        }
        console.log("[!] Falling back to static analysis mode");
        throw error;
      }
    }
  }

  /**
   * Deploy a program to test environment
   * If programPath is a real path, attempts to build and deploy it
   * Otherwise creates a placeholder program ID
   */
  async deployProgram(
    envId: string,
    programPath: string,
    programName: string
  ): Promise<PublicKey> {
    const env = this.environments.get(envId);
    if (!env) {
      throw new Error(`Environment ${envId} not found`);
    }

    console.log(`[*] Deploying ${programName} to test environment...`);
    console.log(`[*] Program path received: ${programPath}`);
    
    // Check if this is a real program path (from Git scan)
    const fs = await import("fs/promises");
    const path = await import("path");
    
    // Normalize and resolve path to absolute
    let normalizedPath = programPath;
    if (!path.isAbsolute(normalizedPath)) {
      normalizedPath = path.resolve(process.cwd(), normalizedPath);
    }
    normalizedPath = path.normalize(normalizedPath);
    
    console.log(`[*] Normalized path: ${normalizedPath}`);
    console.log(`[*] Current working directory: ${process.cwd()}`);
    
    try {
      // Check if path exists and looks like a program
      const pathExists = await fs.access(normalizedPath).then(() => true).catch(() => false);
      
      if (pathExists) {
        console.log(`[*] Path exists, checking for program structure...`);
        // Use normalized path from here on
        programPath = normalizedPath;
        // Check if it's an Anchor workspace (look for Anchor.toml in current dir or parent dirs)
        let anchorWorkspaceRoot: string | null = null;
        let currentCheckPath = programPath;
        
        // Walk up to find Anchor.toml (max 5 levels up)
        for (let i = 0; i < 5; i++) {
          const anchorToml = path.join(currentCheckPath, "Anchor.toml");
          const anchorTomlExists = await fs.access(anchorToml).then(() => true).catch(() => false);
          
          if (anchorTomlExists) {
            anchorWorkspaceRoot = currentCheckPath;
            console.log(`[*] Found Anchor workspace at: ${anchorWorkspaceRoot}`);
            break;
          }
          
          // Check if we're in a programs/ subdirectory - parent should have Anchor.toml
          const parent = path.dirname(currentCheckPath);
          if (parent === currentCheckPath) break; // Reached filesystem root
          currentCheckPath = parent;
        }
        
        if (anchorWorkspaceRoot) {
          console.log(`[*] Detected Anchor program, attempting to build and deploy...`);
          return await this.deployAnchorProgram(envId, programPath, programName, env);
        }
        
        // Check if it's a standalone Rust program (has Cargo.toml in current directory)
        const cargoToml = path.join(programPath, "Cargo.toml");
        const cargoTomlExists = await fs.access(cargoToml).then(() => true).catch(() => false);
        
        if (cargoTomlExists) {
          console.log(`[*] Detected standalone Rust program, attempting to build and deploy...`);
          return await this.deployRustProgram(envId, programPath, programName, env);
        }
        
        // If we have a path but no Anchor.toml or Cargo.toml, log what we found
        console.log(`[!] Path exists but no Anchor.toml or Cargo.toml found at: ${normalizedPath}`);
        console.log(`[!] Listing directory contents...`);
        try {
          const dirContents = await fs.readdir(normalizedPath);
          console.log(`[!] Directory contents: ${dirContents.slice(0, 10).join(", ")}`);
        } catch (e) {
          console.log(`[!] Could not read directory: ${e}`);
        }
        console.log(`[!] Looking for workspace root...`);
      } else {
        console.log(`[!] Program path does not exist: ${normalizedPath}`);
        console.log(`[!] Attempted to access: ${normalizedPath}`);
        console.log(`[!] Original path: ${programPath}`);
        console.log(`[!] CWD: ${process.cwd()}`);
        
        // Try to list parent directory to help debug
        try {
          const parent = path.dirname(normalizedPath);
          if (await fs.access(parent).then(() => true).catch(() => false)) {
            const parentContents = await fs.readdir(parent);
            console.log(`[!] Parent directory exists. Contents: ${parentContents.slice(0, 10).join(", ")}`);
          }
        } catch (e) {
          // Ignore
        }
      }
    } catch (error: any) {
      console.log(`[!] Could not access program path: ${error.message}`);
    }
    
    // Fallback: Generate placeholder program ID
    console.log(`[*] Using placeholder program ID for ${programName}...`);
    const programId = Keypair.generate().publicKey;
    env.deployedPrograms.set(programName, programId);
    console.log(`[+] Program ${programName} (placeholder): ${programId.toBase58().slice(0, 16)}...`);
    console.log(`[!] Note: To test real exploits, provide actual program source code`);
    
    return programId;
  }

  /**
   * Deploy an Anchor program
   */
  private async deployAnchorProgram(
    envId: string,
    programPath: string,
    programName: string,
    env: TestEnvironment
  ): Promise<PublicKey> {
    // OPTIONAL ENHANCEMENT: Check for pre-built binary first (helper programs only)
    // This is a performance optimization, not required for functionality
    if (programName === 'malicious-template' || programName === 'fake-account-generator' || programName === 'overflow-tester') {
      const preBuiltPath = path.join(process.cwd(), 'pre-built-programs', `${programName}.so`);
      const preBuiltKeypair = path.join(process.cwd(), 'pre-built-programs', `${programName}-keypair.json`);
      try {
        await fs.access(preBuiltPath);
        await fs.access(preBuiltKeypair);
        console.log(`[+] Found pre-built binary for ${programName}, using it directly`);
        // Deploy pre-built binary
        const keypairData = JSON.parse(await fs.readFile(preBuiltKeypair, "utf-8"));
        const programKeypair = Keypair.fromSecretKey(Uint8Array.from(keypairData));
        const deployCommand = `solana program deploy "${preBuiltPath}" --program-id "${preBuiltKeypair}" --url http://localhost:8899`;
        await execAsync(deployCommand, { 
          env: { ...process.env, SOLANA_URL: "http://localhost:8899" },
          maxBuffer: 10 * 1024 * 1024
        });
        const programId = programKeypair.publicKey;
        env.deployedPrograms.set(programName, programId);
        console.log(`[+] Pre-built program ${programName} deployed: ${programId.toBase58()}`);
        return programId;
      } catch {
        // Pre-built binary not found, continue with normal build
        console.log(`[*] No pre-built binary found for ${programName}, will build from source`);
      }
    }
    
    // Try Docker first if available
    const useDocker = await this.initDocker();
    
    if (useDocker && this.dockerBuilder) {
      console.log("[*] Using Docker for build (isolated environment, no version conflicts)");
      console.log("[*] Build may take 10-15 minutes on first run (downloading dependencies), 2-5 minutes for cached builds...");
      try {
        const buildStartTime = Date.now();
        const result = await this.dockerBuilder.deployProgram(programPath, programName);
        const buildDuration = ((Date.now() - buildStartTime) / 1000).toFixed(1);
        
        if (result.success && result.programId) {
          const programId = new PublicKey(result.programId);
          env.deployedPrograms.set(programName, programId);
          console.log(`[+] Program ${programName} deployed via Docker: ${programId.toBase58()}`);
          console.log(`[+] Build completed in ${buildDuration} seconds`);
          return programId;
        } else {
          console.log(`[!] Docker build failed after ${buildDuration} seconds`);
          console.log(`[!] Error: ${result.error}`);
          if (result.logs && result.logs.length > 0) {
            console.log(`[!] Last 10 log lines:`);
            result.logs.slice(-10).forEach((line: string) => console.log(`    ${line}`));
          }
          console.log(`[!] Note: Native builds may fail due to Rust version conflicts`);
          console.log(`[!] Recommendation: Fix Docker build or update Solana toolchain`);
          // Still fall through to native build, but warn about likely failure
        }
      } catch (dockerError: any) {
        console.log(`[!] Docker deployment error: ${dockerError.message}`);
        if (dockerError.message.includes("timeout")) {
          console.log(`[!] Build timed out - this can happen on first build or with slow networks`);
          console.log(`[!] You can try:`);
          console.log(`[!]   1. Wait and retry (first build downloads many dependencies)`);
          console.log(`[!]   2. Check Docker container: docker logs anchor-build-env`);
          console.log(`[!]   3. Use native build (may have version conflicts)`);
        }
        console.log(`[!] Falling back to native build`);
        // Fall through to native build
      }
    }

    // Native build (existing code)
    try {
      const { exec } = await import("child_process");
      const { promisify } = await import("util");
      const execAsync = promisify(exec);
      const path = await import("path");
      const fs = await import("fs/promises");
      
      // Find the Anchor workspace root (where Anchor.toml is)
      let workspaceRoot = programPath;
      let currentPath = programPath;
      
      // Walk up the directory tree to find Anchor.toml
      for (let i = 0; i < 5; i++) {
        const anchorToml = path.join(currentPath, "Anchor.toml");
        try {
          await fs.access(anchorToml);
          workspaceRoot = currentPath;
          console.log(`[*] Found Anchor workspace root: ${workspaceRoot}`);
          break;
        } catch {
          // Not found, go up one level
          const parent = path.dirname(currentPath);
          if (parent === currentPath) break; // Reached filesystem root
          currentPath = parent;
        }
      }
      
      // Extract actual program name from the program directory
      // If programPath is like "programs/vault", the program name is "vault"
      let actualProgramName = programName;
      if (programPath.includes("programs")) {
        const programDirName = path.basename(programPath);
        actualProgramName = programDirName;
        console.log(`[*] Detected program name: ${actualProgramName}`);
      }
      
      console.log(`[*] Building Anchor program from workspace root...`);
      console.log(`[*] Workspace: ${workspaceRoot}`);
      console.log(`[*] Program: ${actualProgramName}`);
      
      // Check for anchor command and ensure PATH includes Cargo bin
      let anchorCmd = "anchor";
      const cargoBinPath = process.env.USERPROFILE 
        ? `${process.env.USERPROFILE}\\.cargo\\bin`
        : process.env.HOME 
          ? `${process.env.HOME}/.cargo/bin`
          : null;
      
      // Build environment with Cargo bin and Solana bin in PATH and HOME set (required for Rust/Cargo on Windows)
      const buildEnv: any = { ...process.env };
      const pathSeparator = process.platform === 'win32' ? ';' : ':';
      const pathParts: string[] = [];
      
      // Add Cargo bin to PATH
      if (cargoBinPath) {
        pathParts.push(cargoBinPath);
      }
      
      // Add Solana bin to PATH (required for cargo-build-sbf)
      if (process.platform === 'win32' && process.env.USERPROFILE) {
        const solanaBinPath = `${process.env.USERPROFILE}\\.local\\share\\solana\\install\\active_release\\bin`;
        const fs = await import("fs/promises");
        try {
          await fs.access(solanaBinPath);
          pathParts.push(solanaBinPath);
          console.log(`[*] Added Solana bin to PATH: ${solanaBinPath}`);
        } catch {
          // Solana bin not found, try alternative location
          const altSolanaPath = `${process.env.USERPROFILE}\\AppData\\Local\\Programs\\Solana\\bin`;
          try {
            await fs.access(altSolanaPath);
            pathParts.push(altSolanaPath);
            console.log(`[*] Added Solana bin to PATH: ${altSolanaPath}`);
          } catch {
            console.log(`[!] Solana bin directory not found - cargo-build-sbf may not work`);
          }
        }
      }
      
      // Combine PATH parts
      if (pathParts.length > 0) {
        buildEnv.PATH = `${pathParts.join(pathSeparator)}${pathSeparator}${process.env.PATH || ''}`;
      }
      
      // Always set HOME for Rust/Cargo tools on Windows (required for cargo_build_sbf)
      if (process.platform === 'win32' && process.env.USERPROFILE) {
        buildEnv.HOME = process.env.USERPROFILE;
        // Also ensure USERPROFILE is set (some tools check both)
        buildEnv.USERPROFILE = process.env.USERPROFILE;
        console.log(`[*] Set HOME=${buildEnv.HOME} for Rust/Cargo build tools`);
        
        // Force use of stable Rust toolchain instead of Solana toolchain (1.75.0-dev is too old)
        // This prevents "requires rustc 1.77.0 or newer" errors
        buildEnv.RUSTUP_TOOLCHAIN = "stable";
        console.log(`[*] Forcing stable Rust toolchain (to avoid Solana toolchain version conflicts)`);
        
        // Try to prevent platform-tools installation attempts
        // If platform-tools already exist, cargo-build-sbf should use them
        const solanaBin = `${process.env.USERPROFILE}\\.local\\share\\solana\\install\\active_release\\bin`;
        const platformToolsPath = path.join(solanaBin, 'platform-tools');
        try {
          await fs.access(platformToolsPath);
          console.log(`[*] Platform-tools found - should not need to install`);
          // Set environment to point to existing platform-tools
          buildEnv.SOLANA_PLATFORM_TOOLS = platformToolsPath;
        } catch {
          // Platform-tools don't exist - will need to install (requires admin)
          console.log(`[!] Platform-tools not found - installation may require admin privileges`);
        }
      } else {
        // On non-Windows, also force stable toolchain
        buildEnv.RUSTUP_TOOLCHAIN = "stable";
      }
      
      // First, try to find Anchor with explicit path check
      let anchorExe: string | null = null;
      if (cargoBinPath) {
        const potentialAnchorExe = process.platform === 'win32' 
          ? `${cargoBinPath}\\anchor.exe`
          : `${cargoBinPath}/anchor`;
        
        // Check if file exists
        try {
          await fs.access(potentialAnchorExe);
          anchorExe = potentialAnchorExe;
          console.log(`[*] Found Anchor CLI at: ${anchorExe}`);
          anchorCmd = process.platform === 'win32' ? anchorExe : `"${anchorExe}"`;
        } catch {
          // File doesn't exist, will try PATH
        }
      }
      
      // Try anchor command (either from PATH or explicit path)
      try {
        if (anchorExe) {
          // Use explicit path
          await execAsync(`"${anchorExe}" --version`, { timeout: 5000, env: buildEnv });
          console.log(`[*] Anchor CLI verified at: ${anchorExe}`);
        } else {
          // Try from PATH
          await execAsync("anchor --version", { timeout: 5000, env: buildEnv });
          console.log(`[*] Anchor CLI is available in PATH`);
        }
      } catch (error: any) {
        console.log(`[!] Anchor CLI detection failed: ${error.message}`);
        
        // Last resort: try AVM
        try {
          console.log(`[*] Trying AVM as fallback...`);
          const env = { ...buildEnv, AVM_USE_COPY: "1" };
          await execAsync("avm use latest", { timeout: 10000, env });
          await execAsync("anchor --version", { timeout: 5000, env });
          console.log(`[*] Anchor CLI configured via AVM`);
          anchorCmd = "anchor"; // Reset to use anchor from PATH after AVM setup
        } catch (avmError: any) {
          console.log(`[!] AVM also failed: ${avmError.message}`);
          console.log(`[!] Anchor CLI not found. Expected location: ${cargoBinPath ? `${cargoBinPath}\\anchor.exe` : 'unknown'}`);
          console.log(`[!] To fix:`);
          console.log(`[!]   1. Verify Anchor is installed: cargo install --git https://github.com/coral-xyz/anchor anchor-cli --locked`);
          console.log(`[!]   2. Or add Cargo bin to system PATH: $env:Path += ";$env:USERPROFILE\.cargo\bin"`);
          throw new Error(`Anchor CLI not found. Please install or add to PATH.`);
        }
      }
      
      // Create rust-toolchain.toml in workspace to force stable Rust
      // This prevents Anchor from using the old Solana toolchain (1.75.0-dev)
      const rustToolchainFile = path.join(workspaceRoot, "rust-toolchain.toml");
      const fsPromises = await import("fs/promises");
      try {
        await fsPromises.writeFile(
          rustToolchainFile,
          `[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
`,
          "utf-8"
        );
        console.log(`[*] Created rust-toolchain.toml to force stable Rust`);
      } catch (toolchainError: any) {
        console.log(`[!] Could not create rust-toolchain.toml: ${toolchainError.message}`);
        // Continue anyway - RUSTUP_TOOLCHAIN env var should still work
      }
      
      // Build the program from workspace root using cargo build-sbf directly
      // CRITICAL FIX: Use cargo build-sbf --workspace instead of anchor build
      // This completely bypasses Anchor's toolchain activation, solving the 1.75.0-dev issue
      
      // Helper function to find program Cargo.toml and build individually
      const findProgramAndBuild = async (): Promise<string> => {
        try {
          const { execSync } = await import("child_process");
          const findCommand = process.platform === 'win32'
            ? `dir /s /b "${workspaceRoot}\\programs\\*Cargo.toml" | findstr /v node_modules | findstr /v target`
            : `find "${workspaceRoot.replace(/\\/g, '/')}/programs" -name Cargo.toml -type f 2>/dev/null | head -1`;
          
          const programPath = execSync(findCommand, {
            encoding: 'utf-8',
            cwd: workspaceRoot,
            maxBuffer: 10 * 1024 * 1024
          }).toString().trim();
          
          if (!programPath) {
            throw new Error('No program Cargo.toml found');
          }
          
          const programDir = path.dirname(programPath);
          return `cd "${programDir}" && cargo build-sbf --sbf-out-dir "${workspaceRoot}/target/deploy"`;
        } catch (error: any) {
          throw new Error(`Could not find program Cargo.toml: ${error.message}`);
        }
      };
      
      // Build commands - try workspace first, then individual program
      const buildCommandMethods = [
        {
          name: 'cargo build-sbf --workspace',
          getCommand: async () => "cargo build-sbf --workspace --sbf-out-dir ./target/deploy"
        },
        {
          name: 'cargo build-sbf (individual program)',
          getCommand: findProgramAndBuild
        }
      ];
      
      // Ensure rust-toolchain.toml exists and is correct before building
      try {
        const toolchainContent = await fsPromises.readFile(rustToolchainFile, "utf-8");
        if (!toolchainContent.includes("stable")) {
          await fsPromises.writeFile(rustToolchainFile, `[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
`, "utf-8");
          console.log(`[*] Updated rust-toolchain.toml to force stable`);
        }
      } catch {
        // File doesn't exist or can't be read, try to create it again
        try {
          await fsPromises.writeFile(rustToolchainFile, `[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
`, "utf-8");
          console.log(`[*] Created rust-toolchain.toml to force stable Rust`);
        } catch (toolchainError: any) {
          console.log(`[!] Could not create rust-toolchain.toml: ${toolchainError.message}`);
        }
      }
      
      // Also set CARGO_BUILD_RUSTC to ensure we use stable
      buildEnv.CARGO_BUILD_RUSTC = "rustc";
      buildEnv.CARGO = "cargo";
      
      // Prevent Anchor from installing Solana toolchain by setting override
      // Anchor checks for RUSTUP_TOOLCHAIN and should respect it
      // Also set override in the workspace directory
      try {
        const overrideCommand = `rustup override set stable --path "${workspaceRoot}"`;
        await execAsync(overrideCommand, { env: buildEnv, timeout: 5000 });
        console.log(`[*] Set rustup override to stable for workspace`);
      } catch (overrideError: any) {
        console.log(`[!] Could not set rustup override: ${overrideError.message}`);
        // Continue anyway
      }
      
      // Use ToolchainHelper to ensure stable toolchain (removes Solana toolchain)
      try {
        const { ToolchainHelper } = await import("../utils/toolchain-helper.js");
        ToolchainHelper.ensureStableToolchain();
        // Merge toolchain helper's environment settings
        const stableEnv = ToolchainHelper.getStableBuildEnv();
        Object.assign(buildEnv, stableEnv);
      } catch (importError: any) {
        // Fallback to manual toolchain management if helper not available
        console.log(`[!] ToolchainHelper not available, using manual toolchain management`);
        try {
          const { stdout } = await execAsync("rustup toolchain list", { env: buildEnv, timeout: 5000 });
          if (stdout.includes("solana")) {
            console.log(`[*] Removing Solana toolchain to prevent version conflicts...`);
            try {
              await execAsync("rustup toolchain uninstall solana", { env: buildEnv, timeout: 10000 });
              console.log(`[*] Solana toolchain removed`);
            } catch (uninstallError: any) {
              console.log(`[!] Could not remove Solana toolchain: ${uninstallError.message}`);
            }
          }
        } catch (toolchainCheckError: any) {
          // Ignore - rustup might not be available
        }
        buildEnv.SKIP_SOLANA_TOOLCHAIN = "1";
        buildEnv.ANCHOR_SKIP_SOLANA_INSTALL = "1";
      }
      
      // Set environment variables to prevent Anchor from installing Solana toolchain
      buildEnv.RUSTUP_TOOLCHAIN = buildEnv.RUSTUP_TOOLCHAIN || "stable";
      buildEnv.CARGO_BUILD_SBF_USE_SYSTEM_RUST = "true";
      
      console.log(`[*] Using Rust toolchain: ${buildEnv.RUSTUP_TOOLCHAIN || 'stable (via rust-toolchain.toml)'}`);

      let buildOutput: any;
      let lastError: any = null;

      // Try build command methods in sequence until one succeeds
      for (let i = 0; i < buildCommandMethods.length; i++) {
        const method = buildCommandMethods[i];
        
        try {
          // Get the command string from the method
          const buildCommand = await method.getCommand();
          console.log(`[*] Attempting build method ${i + 1}/${buildCommandMethods.length}: ${method.name}`);
          console.log(`[*] Command: ${buildCommand}`);

          buildOutput = await execAsync(buildCommand, {
            cwd: workspaceRoot,
            env: buildEnv,
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer for build output
          });
          console.log(`[*] Build completed successfully using method ${i + 1}`);
          
          // Generate IDL separately after successful build
          try {
            console.log(`[*] Generating IDL separately...`);
            const idlCommand = anchorExe && process.platform === 'win32'
              ? `"${anchorExe}" idl build`
              : `${anchorCmd} idl build`;
            await execAsync(idlCommand, {
              cwd: workspaceRoot,
              env: buildEnv,
              maxBuffer: 10 * 1024 * 1024
            });
            console.log(`[+] IDL generated successfully`);
          } catch (idlError: any) {
            console.log(`[!] IDL generation failed (non-critical): ${idlError.message}`);
            // Continue - IDL generation failure is not critical for deployment
          }
          
          break; // Success, exit the loop
        } catch (buildError: any) {
          console.log(`[!] Build method ${i + 1} (${method.name}) failed: ${buildError.message}`);
          lastError = buildError;

          // Continue to next method if this one failed
          if (i < buildCommandMethods.length - 1) {
            console.log(`[*] Trying next build method...`);
          }
        }
      }

      // If all build methods failed, handle the error
      if (!buildOutput) {
        console.log(`[!] All build methods failed. Last error: ${lastError?.message}`);
        // Set buildError for the existing error handling logic
        var buildError = lastError;
        // Check if error is about platform-tools installation (privilege error)
        const errorMessage = buildError.stderr || buildError.message || '';
        if (errorMessage.includes('Failed to install platform-tools') || 
            errorMessage.includes('os error 1314') ||
            errorMessage.includes('required privilege')) {
          console.log(`[!] Platform-tools installation/update failed (requires admin privileges)`);
          console.log(`[!] Note: Platform-tools v1.41 is embedded in cargo-build-sbf`);
          console.log(`[!] This error may occur if Anchor tries to update platform-tools`);
          console.log(`[!] Attempting workaround: Using existing cargo-build-sbf tools...`);
          
          // Try to work around by ensuring cargo-build-sbf uses its embedded tools
          // The issue is that cargo-build-sbf tries to install/update platform-tools
          // but they're already embedded, so this should work
          const solanaBin = process.env.USERPROFILE 
            ? `${process.env.USERPROFILE}\\.local\\share\\solana\\install\\active_release\\bin`
            : null;
          
          if (solanaBin) {
            // Ensure cargo-build-sbf is in PATH and can find its embedded tools
            const enhancedEnv = { ...buildEnv };
            // Add explicit path to cargo-build-sbf
            enhancedEnv.PATH = `${solanaBin};${enhancedEnv.PATH || ''}`;
            
            console.log(`[*] Retrying build with enhanced PATH...`);
            try {
              // Retry with first build method
              const retryMethod = buildCommandMethods[0];
              const retryCommand = await retryMethod.getCommand();
              buildOutput = await execAsync(retryCommand, {
                cwd: workspaceRoot,
                env: enhancedEnv,
                maxBuffer: 10 * 1024 * 1024
              });
              console.log(`[*] Build completed on retry`);
            } catch (retryError: any) {
              // If it still fails, the platform-tools installation is blocking the build
              console.log(`[!] Build still failing - platform-tools installation is required`);
              console.log(`[!] Solution: Run 'solana-install update' as Administrator once`);
              console.log(`[!] After that, builds should work without admin privileges`);
              throw buildError;
            }
          } else {
            throw buildError;
          }
        } else {
          // Different error - throw it
          throw buildError;
        }
      }
      
      // Find the built .so file (Anchor builds to workspace root/target/deploy/)
      const soFile = path.join(workspaceRoot, "target", "deploy", `${actualProgramName}.so`);
      const keypairFile = path.join(workspaceRoot, "target", "deploy", `${actualProgramName}-keypair.json`);
      
      // Check if files exist
      try {
        await fs.access(soFile);
        await fs.access(keypairFile);
      } catch (error: any) {
        throw new Error(`Build artifacts not found. Expected:\n  ${soFile}\n  ${keypairFile}\n\nBuild may have failed. Check Anchor.toml configuration.`);
      }
      
      // Read the program keypair
      const keypairData = JSON.parse(await fs.readFile(keypairFile, "utf-8"));
      const programKeypair = Keypair.fromSecretKey(Uint8Array.from(keypairData));
      
      console.log(`[*] Deploying to validator...`);
      console.log(`[*] Program ID: ${programKeypair.publicKey.toBase58()}`);
      
      // Deploy using solana program deploy (use buildEnv with PATH and HOME)
      const deployCommand = `solana program deploy "${soFile}" --program-id "${keypairFile}" --url http://localhost:8899`;
      await execAsync(deployCommand, { 
        cwd: workspaceRoot,
        env: { ...buildEnv, SOLANA_URL: "http://localhost:8899" },
        maxBuffer: 10 * 1024 * 1024
      });
      
      const programId = programKeypair.publicKey;
      
      // CRITICAL: Verify program is actually loaded in validator runtime
      console.log(`[*] Verifying program is loaded in validator runtime...`);
      const connection = new Connection("http://localhost:8899", "confirmed");
      let isLoaded = false;
      let isExecutable = false;
      
      // Retry up to 10 times with 1 second delay
      for (let attempt = 1; attempt <= 10; attempt++) {
        try {
          const accountInfo = await connection.getAccountInfo(programId);
          if (accountInfo) {
            isLoaded = true;
            if (accountInfo.executable === true) {
              isExecutable = true;
              console.log(`[+] Program verified: loaded and executable in validator runtime`);
              break;
            } else {
              console.log(`[*] Program exists but not executable yet (attempt ${attempt}/10)...`);
            }
          } else {
            console.log(`[*] Program not found yet (attempt ${attempt}/10)...`);
          }
        } catch (error: any) {
          console.log(`[!] Error checking program (attempt ${attempt}/10): ${error.message}`);
        }
        
        if (attempt < 10) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
      
      if (!isLoaded) {
        throw new Error(`Program deployment failed: Program ${programId.toBase58().slice(0, 16)}... not found in validator after deployment`);
      }
      
      if (!isExecutable) {
        throw new Error(`Program deployment incomplete: Program ${programId.toBase58().slice(0, 16)}... exists but is not executable`);
      }
      
      env.deployedPrograms.set(programName, programId);
      console.log(`[+] Program ${actualProgramName} deployed and verified: ${programId.toBase58()}`);
      
      return programId;
    } catch (error: any) {
      console.log(`[!] Failed to deploy Anchor program: ${error.message}`);
      if (error.stdout) {
        console.log(`[!] Build output: ${error.stdout}`);
      }
      if (error.stderr) {
        console.log(`[!] Build errors: ${error.stderr}`);
      }
      console.log(`[!] Common issues:`);
      console.log(`[!]   1. Anchor CLI not installed: cargo install --git https://github.com/coral-xyz/anchor avm --locked --force`);
      console.log(`[!]   2. Program dependencies not installed: cd to workspace and run 'anchor build' manually`);
      console.log(`[!]   3. Program name mismatch: Check Anchor.toml [programs.localnet] section`);
      console.log(`[!]   4. Solana CLI not in PATH: Install from https://docs.solana.com/cli/install-solana-cli-tools`);
      console.log(`[!] Falling back to placeholder...`);
      // Fallback to placeholder
      const programId = Keypair.generate().publicKey;
      env.deployedPrograms.set(programName, programId);
      return programId;
    }
  }

  /**
   * Deploy a Rust program (non-Anchor)
   */
  private async deployRustProgram(
    envId: string,
    programPath: string,
    programName: string,
    env: TestEnvironment
  ): Promise<PublicKey> {
    // For now, return placeholder
    // Full Rust program deployment would require cargo build-sbf
    console.log(`[!] Rust program deployment not yet implemented`);
    const programId = Keypair.generate().publicKey;
    env.deployedPrograms.set(programName, programId);
    return programId;
  }

  /**
   * Deploy helper programs based on vulnerability type
   * Only deploys what's needed for the specific vulnerability
   */
  async deployHelperPrograms(
    envId: string,
    programTypes: {
      maliciousProgram?: boolean;
      fakeAccountGenerator?: boolean;
      overflowTester?: boolean;
    }
  ): Promise<{
    maliciousProgram?: PublicKey;
    fakeAccountGenerator?: PublicKey;
    overflowTester?: PublicKey;
  }> {
    const env = this.environments.get(envId);
    if (!env) {
      throw new Error(`Environment ${envId} not found`);
    }

    const result: {
      maliciousProgram?: PublicKey;
      fakeAccountGenerator?: PublicKey;
      overflowTester?: PublicKey;
    } = {};

    // Only deploy programs that are needed
    if (programTypes.maliciousProgram) {
      result.maliciousProgram = await this.deployProgram(
        envId,
        "./test-programs/malicious-template",
        "malicious-template"
      );
    }
    
    if (programTypes.fakeAccountGenerator) {
      result.fakeAccountGenerator = await this.deployProgram(
        envId,
        "./test-programs/fake-account-generator",
        "fake-account-generator"
      );
    }
    
    if (programTypes.overflowTester) {
      result.overflowTester = await this.deployProgram(
        envId,
        "./test-programs/overflow-tester",
        "overflow-tester"
      );
    }

    return result;
  }

  /**
   * Cleanup test environment
   */
  private async cleanupEnvironment(envId: string): Promise<void> {
    const env = this.environments.get(envId);
    if (env) {
      env.deployedPrograms.clear();
      this.environments.delete(envId);
    }

    // Stop validator process if we started it
    const process = this.validatorProcesses.get(envId);
    if (process) {
      process.kill();
      this.validatorProcesses.delete(envId);
    }
  }

  /**
   * Get environment by ID
   */
  getEnvironment(envId: string): TestEnvironment | undefined {
    return this.environments.get(envId);
  }
}

