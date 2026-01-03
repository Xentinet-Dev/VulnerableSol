import simpleGit, { SimpleGit } from "simple-git";
import * as fs from "fs/promises";
import * as path from "path";
import { glob } from "glob";
import { ScanResult, Vulnerability, Severity } from "../types/vulnerability.js";
import { BaseDetector } from "../detectors/base-detector.js";
// Detectors are loaded dynamically to avoid circular dependencies
import ora from "ora";
import { generateIdlFromSource } from "../idl/idl-generator.js";

/**
 * Scanner for Git repositories
 */
export class GitScanner {
  private detectors: BaseDetector[] = [];
  private tempDir: string;
  private preserveRepos: boolean;

  constructor(tempDir: string = "./.scan-temp", preserveRepos: boolean = false) {
    this.tempDir = tempDir;
    this.preserveRepos = preserveRepos;
    // Detectors will be initialized on first use
  }

  /**
   * Enable repository preservation for testing
   */
  public enableRepoPreservation(): void {
    this.preserveRepos = true;
  }

  /**
   * Disable repository preservation (default secure behavior)
   */
  public disableRepoPreservation(): void {
    this.preserveRepos = false;
  }

  /**
   * Clean up preserved repositories (call manually when testing is complete)
   */
  public async cleanupPreservedRepos(): Promise<void> {
    try {
      console.log(`🧹 Cleaning up preserved repositories in ${this.tempDir}...`);
      const entries = await fs.readdir(this.tempDir).catch(() => []);
      let cleanedCount = 0;

      for (const entry of entries) {
        const fullPath = path.join(this.tempDir, entry);
        try {
          const stat = await fs.stat(fullPath).catch(() => null);
          if (stat?.isDirectory()) {
            await fs.rm(fullPath, { recursive: true, force: true });
            cleanedCount++;
            console.log(`✅ Cleaned up: ${entry}`);
          }
        } catch (error) {
          console.warn(`Warning: Could not remove ${fullPath}: ${error}`);
        }
      }

      if (cleanedCount > 0) {
        console.log(`🧹 Successfully cleaned up ${cleanedCount} preserved repositories`);
      } else {
        console.log(`ℹ️ No preserved repositories found to clean up`);
      }
    } catch (error) {
      console.error(`❌ Failed to clean up preserved repositories: ${error}`);
    }
  }

  private async initializeDetectors(): Promise<void> {
    if (this.detectors.length > 0) return; // Already initialized

    const { ReentrancyDetector, WeakOracleDetector } = await import("../detectors/evm-detectors.js");
    const { 
      MissingSignerCheckDetector, 
      MissingOwnershipCheckDetector,
      ReinitializationDetector,
      IntegerOverflowDetector,
      PDAAbuseDetector,
      ExternalProgramValidationDetector,
      AccountStructureValidationDetector
    } = await import("../detectors/solana-detectors.js");
    const {
      SupplyChainDetector,
      XSSDetector,
      WalletIntegrationDetector
    } = await import("../detectors/dapp-detectors.js");
    const {
      CastTruncationDetector,
      CloseAccountDetector,
      DuplicatedAccountDetector,
      ErrorHandlingDetector,
      RoundingDetector
    } = await import("../detectors/advanced-solana-detectors.js");
    const {
      SysvarSpoofingDetector,
      AccountCloseDetector,
      DuplicateAccountsDetector,
      Token2022Detector,
      AddressPoisoningDetector,
      PDACollisionDetector,
      OracleManipulationDetector,
      ReentrancyEnhancedDetector,
      InitializationAttackDetector,
      ArithmeticEnhancedDetector,
      MEVFrontrunningDetector,
      UpgradeAuthorityDetector
    } = await import("../detectors/critical-vulnerability-detectors.js");

    this.detectors = [
      new MissingSignerCheckDetector(),
      new MissingOwnershipCheckDetector(),
      new ReinitializationDetector(),
      new IntegerOverflowDetector(),
      new PDAAbuseDetector(),
      new ExternalProgramValidationDetector(),
      new AccountStructureValidationDetector(),
      new CastTruncationDetector(),
      new CloseAccountDetector(),
      new DuplicatedAccountDetector(),
      new ErrorHandlingDetector(),
      new RoundingDetector(),
      new ReentrancyDetector(),
      new WeakOracleDetector(),
      new SupplyChainDetector(),
      new XSSDetector(),
      new WalletIntegrationDetector(),
      // New critical vulnerability detectors
      new SysvarSpoofingDetector(),
      new AccountCloseDetector(),
      new DuplicateAccountsDetector(),
      new Token2022Detector(),
      new AddressPoisoningDetector(),
      new PDACollisionDetector(),
      new OracleManipulationDetector(),
      new ReentrancyEnhancedDetector(),
      new InitializationAttackDetector(),
      new ArithmeticEnhancedDetector(),
      new MEVFrontrunningDetector(),
      new UpgradeAuthorityDetector()
    ];
  }

  /**
   * Scan a Git repository
   */
  async scanRepository(repoUrl: string, branch?: string, enableTesting: boolean = false): Promise<ScanResult> {
    await this.initializeDetectors();

    // Handle repository preservation for testing
    if (enableTesting) {
      console.warn(`⚠️  SECURITY WARNING: Repository preservation enabled for this scan`);
      console.warn(`⚠️  This keeps potentially vulnerable code on disk after scanning`);
      console.warn(`⚠️  Only use this for controlled testing environments`);
      console.warn(`⚠️  Call POST /api/cleanup-repos when testing is complete`);
    }

    const spinner = ora(`Cloning repository: ${repoUrl}`).start();
    
    try {
      // Create temp directory
      await fs.mkdir(this.tempDir, { recursive: true });
      const repoName = this.extractRepoName(repoUrl);
      const repoPath = path.join(this.tempDir, repoName);

      // Check if repo already exists (from previous failed clone)
      try {
        const exists = await fs.access(repoPath).then(() => true).catch(() => false);
        if (exists) {
          spinner.text = `Cleaning up previous clone attempt...`;
          await fs.rm(repoPath, { recursive: true, force: true });
        }
      } catch (e) {
        // Ignore cleanup errors
      }

      // Clone repository with timeout and shallow clone for speed
      const git: SimpleGit = simpleGit();
      
      // Use shallow clone (depth=1) for faster cloning - we only need latest code
      spinner.text = `Cloning repository (shallow clone, 2min timeout): ${repoUrl}`;
      
      try {
        // Add timeout wrapper (2 minutes max)
        const clonePromise = git.clone(repoUrl, repoPath, ['--depth', '1', '--single-branch']);
        const timeoutPromise = new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Clone timeout: Repository took longer than 2 minutes to clone. Try again or check network connection.')), 120000)
        );
        
        await Promise.race([clonePromise, timeoutPromise]);
      } catch (error: any) {
        // Clean up partial clone on error
        try {
          await fs.rm(repoPath, { recursive: true, force: true });
        } catch (e) {
          // Ignore cleanup errors
        }
        throw error;
      }
      
      // Change to repo directory
      const repoGit = simpleGit(repoPath);
      
      // Handle checkout - may fail on Windows due to invalid paths (e.g., colons in filenames)
      let checkoutWarning = false;
      if (branch) {
        try {
          // Check if branch exists (local or remote)
          const branches = await repoGit.branchLocal();
          const remoteBranches = await repoGit.branch(["-r"]);
          
          const branchExists = 
            branches.all.includes(branch) || 
            remoteBranches.all.some(b => b.includes(`/${branch}`));
          
          if (branchExists) {
            try {
              await repoGit.checkout(branch);
              spinner.text = `Checked out branch: ${branch}`;
            } catch (checkoutError: any) {
              // Checkout may fail on Windows due to invalid paths (colons, etc.)
              if (checkoutError.message?.includes("invalid path") || 
                  checkoutError.message?.includes("unable to checkout")) {
                checkoutWarning = true;
                spinner.warn(`Checkout failed due to invalid Windows paths (e.g., colons in filenames). Continuing with available files...`);
                // Try to restore what we can
                try {
                  await repoGit.raw(['restore', '--source=HEAD', ':/']);
                } catch (restoreError) {
                  // Ignore restore errors - we'll scan what we have
                }
              } else {
                throw checkoutError;
              }
            }
          } else {
            spinner.warn(`Branch '${branch}' not found, using default branch`);
            // Try common default branch names
            const defaultBranches = ["main", "master", "develop", "dev"];
            let checkedOut = false;
            
            for (const defaultBranch of defaultBranches) {
              try {
                const allBranches = await repoGit.branch(["-a"]);
                if (allBranches.all.some(b => b.includes(defaultBranch))) {
                  try {
                    await repoGit.checkout(defaultBranch);
                    spinner.text = `Using default branch: ${defaultBranch}`;
                    checkedOut = true;
                    break;
                  } catch (checkoutError: any) {
                    if (checkoutError.message?.includes("invalid path") || 
                        checkoutError.message?.includes("unable to checkout")) {
                      checkoutWarning = true;
                      spinner.warn(`Checkout failed due to invalid Windows paths. Continuing with available files...`);
                      checkedOut = true; // Consider it "checked out" even if some files failed
                      break;
                    }
                    // Try next branch
                  }
                }
              } catch (e) {
                // Try next branch
              }
            }
            
            if (!checkedOut) {
              // Just use whatever branch is currently checked out
              spinner.text = "Using current branch";
            }
          }
        } catch (error: any) {
          // Check if it's a checkout error with invalid paths
          if (error.message?.includes("invalid path") || 
              error.message?.includes("unable to checkout")) {
            checkoutWarning = true;
            spinner.warn(`Checkout failed due to invalid Windows paths. Continuing with available files...`);
          } else {
            spinner.warn(`Could not checkout branch '${branch}': ${error}. Using default branch`);
          }
        }
      }

      if (checkoutWarning) {
        spinner.warn(`Repository cloned, but some files couldn't be checked out (invalid Windows paths). Scanning available files...`);
      } else {
        spinner.succeed(`Repository cloned successfully`);
      }

      // Find all contract files
      const contractFiles = await this.findContractFiles(repoPath);
      
      spinner.start(`Scanning ${contractFiles.length} contract files...`);

      // Scan each file
      const allVulnerabilities: Vulnerability[] = [];

      for (const file of contractFiles) {
        try {
          // Check if path is actually a file (not a directory or symlink to directory)
          const stats = await fs.stat(file);
          if (!stats.isFile()) {
            // Skip directories and other non-file entries
            continue;
          }
          
          const content = await fs.readFile(file, "utf-8");
          const relativePath = path.relative(repoPath, file);

          for (const detector of this.detectors) {
            if (detector.isApplicable(file)) {
              const vulns = await detector.detect(content, {
                filePath: relativePath,
                fullPath: file
              });
              
              // Add repository path to each vulnerability for simulation (use absolute path)
              for (const vuln of vulns) {
                if (!vuln.metadata) vuln.metadata = {};
                // Ensure absolute path for cross-platform compatibility
                const absoluteRepoPath = path.isAbsolute(repoPath) 
                  ? repoPath 
                  : path.resolve(process.cwd(), repoPath);
                vuln.metadata.repositoryPath = absoluteRepoPath;
                vuln.metadata.repositoryUrl = repoUrl;
                vuln.metadata.sourceFile = file;
              }
              
              allVulnerabilities.push(...vulns);
            }
          }
        } catch (error: any) {
          // Only log if it's not a "directory" error (we skip those silently)
          if (error.code !== 'EISDIR') {
            console.error(`Error scanning ${file}:`, error);
          }
        }
      }

      spinner.succeed(`Scan complete`);

      // PHASE 1 IMPROVEMENT: Generate IDL during scan phase (when repository is available)
      // This avoids needing to re-clone or regenerate IDL during simulation
      let cachedIdl: any = null;
      let idlSource: "repo" | "generated" | "chain" | "inferred-bpf" | "cached" | null = null;
      
      if (enableTesting) {
        try {
          spinner.start(`Generating IDL during scan phase (repository available)...`);
          const idlResult = await generateIdlFromSource({
            repoPath: repoPath,
            useDocker: true
          });
          
          if (idlResult.success && idlResult.idl) {
            cachedIdl = idlResult.idl;
            idlSource = "generated";
            spinner.succeed(`IDL generated and cached during scan phase`);
            
            // Store IDL in all vulnerabilities' metadata for simulator access
            for (const vuln of allVulnerabilities) {
              if (!vuln.metadata) {
                vuln.metadata = {};
              }
              vuln.metadata.cachedIdl = cachedIdl;
              vuln.metadata.idlSource = idlSource;
            }
          } else {
            spinner.warn(`IDL generation during scan failed (non-critical): ${idlResult.error || 'Unknown error'}`);
            // Continue without IDL - simulator will try to generate it later
          }
        } catch (idlError: any) {
          spinner.warn(`IDL generation error during scan (non-critical): ${idlError.message}`);
          // Continue without IDL - simulator will try to generate it later
        }
      }

      // Don't cleanup immediately - keep repo for simulation
      // Repos will be cleaned up on next scan or after simulation
      // Store repo path in metadata for simulator to use
      
      // Ensure absolute path in result metadata
      const absoluteRepoPath = path.isAbsolute(repoPath)
        ? repoPath
        : path.resolve(process.cwd(), repoPath);

      // Handle repository preservation for testing
      if (!enableTesting) {
        try {
          spinner.text = `Cleaning up repository for security...`;
          await fs.rm(repoPath, { recursive: true, force: true });
          spinner.succeed(`Repository cleaned up for security`);
        } catch (error) {
          console.warn(`Failed to cleanup ${repoPath}:`, error);
        }
      } else {
        spinner.succeed(`Repository preserved for testing (⚠️ SECURITY RISK)`);
        console.warn(`🚨 REPOSITORY PRESERVED: ${repoPath}`);
        console.warn(`🚨 This contains potentially vulnerable code`);
        console.warn(`🚨 Use POST /api/cleanup-repos to remove when testing complete`);
      }

      return this.buildResult("git", repoUrl, allVulnerabilities, {
        repository: repoUrl,
        repositoryPath: absoluteRepoPath, // Keep absolute path for simulation
        branch: branch || "default",
        filesScanned: contractFiles.length,
        cachedIdl: cachedIdl, // Store IDL at scan result level too
        idlSource: idlSource
      });
    } catch (error) {
      spinner.fail(`Error scanning repository: ${error}`);
      throw error;
    }
  }

  /**
   * Find all contract files in the repository
   */
  private async findContractFiles(repoPath: string): Promise<string[]> {
    const patterns = [
      "**/*.sol",           // Solidity
      "**/*.rs",            // Rust (Solana)
      "**/lib.rs",          // Anchor programs
      "**/programs/**/*.rs", // Anchor structure
      "**/Cargo.toml"       // Rust projects
    ];

    const files: string[] = [];

    for (const pattern of patterns) {
      const matches = await glob(pattern, {
        cwd: repoPath,
        absolute: true,
        ignore: ["**/node_modules/**", "**/target/**", "**/.git/**"],
        // Only match files, not directories
        nodir: true
      });
      files.push(...matches);
    }

    // Filter out any directories that might have slipped through
    const fileStats = await Promise.allSettled(
      files.map(async (file) => {
        const stats = await fs.stat(file);
        return stats.isFile() ? file : null;
      })
    );

    const validFiles = fileStats
      .filter((result): result is PromiseFulfilledResult<string> => 
        result.status === 'fulfilled' && result.value !== null
      )
      .map(result => result.value);

    return [...new Set(validFiles)]; // Remove duplicates
  }

  /**
   * Extract repository name from URL
   */
  private extractRepoName(repoUrl: string): string {
    const match = repoUrl.match(/([^/]+)\.git$/) || repoUrl.match(/([^/]+)$/);
    return match ? match[1] : "repository";
  }

  /**
   * Cleanup temporary files
   */
  private async cleanup(repoPath: string): Promise<void> {
    try {
      await fs.rm(repoPath, { recursive: true, force: true });
    } catch (error) {
      console.warn(`Failed to cleanup ${repoPath}:`, error);
    }
  }

  private buildResult(
    targetType: "contract" | "git" | "url",
    target: string,
    vulnerabilities: Vulnerability[],
    metadata?: any
  ): ScanResult {
    const summary = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === Severity.CRITICAL).length,
      high: vulnerabilities.filter(v => v.severity === Severity.HIGH).length,
      medium: vulnerabilities.filter(v => v.severity === Severity.MEDIUM).length,
      low: vulnerabilities.filter(v => v.severity === Severity.LOW).length,
      info: vulnerabilities.filter(v => v.severity === Severity.INFO).length
    };

    // Note: Repository preservation is handled per-scan, not per-instance

    return {
      target,
      targetType,
      timestamp: new Date(),
      vulnerabilities,
      summary,
      metadata
    };
  }
}

