import { Connection, PublicKey } from "@solana/web3.js";
import { JsonRpcProvider } from "ethers";
import { ScanResult, Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { BaseDetector } from "../detectors/base-detector.js";
import { IdlFetcher } from "../idl/idl-fetcher.js";
import * as path from "path";
// Detectors are loaded dynamically

/**
 * Scanner for on-chain contract addresses
 */
export class ContractScanner {
  private detectors: BaseDetector[] = [];
  private solanaConnection?: Connection;
  private evmProvider?: JsonRpcProvider;

  constructor(solanaRpcUrl?: string, evmRpcUrl?: string) {
    // Detectors will be initialized on first use

    if (solanaRpcUrl) {
      this.solanaConnection = new Connection(solanaRpcUrl, "confirmed");
    }

    if (evmRpcUrl) {
      this.evmProvider = new JsonRpcProvider(evmRpcUrl);
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
   * Scan a Solana program address
   * @param address - Solana program address
   * @param repoPath - Optional path to repository (for IDL fetching)
   * @param bpfPath - Optional path to BPF binary (for IDL inference)
   */
  async scanSolanaContract(
    address: string,
    repoPath?: string,
    bpfPath?: string
  ): Promise<ScanResult> {
    await this.initializeDetectors();
    if (!this.solanaConnection) {
      throw new Error("Solana RPC URL not configured");
    }

    const publicKey = new PublicKey(address);
    const accountInfo = await this.solanaConnection.getAccountInfo(publicKey);

    if (!accountInfo) {
      throw new Error(`Contract not found at address: ${address}`);
    }

    // Fetch IDL using all strategies
    let idlInfo = null;
    const context: any = {};

    try {
      idlInfo = await IdlFetcher.getIdl({
        programId: address,
        repoPath: repoPath,
        bpfPath: bpfPath,
        connection: this.solanaConnection,
      });

      if (idlInfo) {
        console.log(
          `Loaded IDL from ${idlInfo.source}: ${idlInfo.idl.name || "unknown"}`
        );
        context.idl = idlInfo.idl; // Pass to detectors + exploit engines
      } else {
        console.log("No IDL found (repo, chain, BPF inference all failed).");
      }
    } catch (err: any) {
      console.log("IDL fetch failed:", err instanceof Error ? err.message : String(err));
    }

    // For Solana, we can analyze bytecode or try to fetch source
    // In practice, you'd want to use a decompiler or fetch verified source
    const vulnerabilities: Vulnerability[] = [];

    // Check if it's a program (executable)
    if (accountInfo.executable) {
      // Analyze bytecode patterns (simplified - in practice use proper decompiler)
      const bytecode = Buffer.from(accountInfo.data).toString("hex");
      
      // Run detectors that can work with bytecode/metadata
      // Since we need source code for full analysis, flag for manual review
      const solanaDetectorNames = ["Missing Signer Check", "Missing Ownership Check"];
      const hasSolanaDetectors = this.detectors.some(d => solanaDetectorNames.includes(d.name));
      
      if (hasSolanaDetectors) {
        const vuln: Vulnerability = {
          id: `solana-contract-${address}-manual-review`,
          title: "Manual Review Required",
          description: "Source code not available. Manual review recommended to check for Solana account lifecycle vulnerabilities.",
          severity: Severity.INFO,
          category: VulnerabilityCategory.SOLANA_ACCOUNT_LIFECYCLE,
          location: {
            contract: address
          },
          recommendation: "Review source code (if verified) or decompile bytecode to check for missing signer checks, ownership validation, and account lifecycle issues."
        };

        // Add IDL info to vulnerability metadata if available
        if (idlInfo) {
          vuln.metadata = {
            idlSource: idlInfo.source,
            idl: idlInfo.idl
          };
        }

        vulnerabilities.push(vuln);
      }
    }

    const metadata: any = {
      contractAddress: address,
      network: "solana",
      executable: accountInfo.executable,
      owner: accountInfo.owner.toString()
    };

    // Add IDL info to scan result metadata
    if (idlInfo) {
      metadata.idlSource = idlInfo.source;
      metadata.hasIdl = true;
    }

    return this.buildResult("contract", address, vulnerabilities, metadata);
  }

  /**
   * Scan an EVM contract address
   */
  async scanEVMContract(address: string, network: string = "ethereum"): Promise<ScanResult> {
    await this.initializeDetectors();
    if (!this.evmProvider) {
      throw new Error("EVM RPC URL not configured");
    }

    // Fetch bytecode
    const bytecode = await this.evmProvider.getCode(address);
    
    if (!bytecode || bytecode === "0x") {
      throw new Error(`No contract found at address: ${address}`);
    }

    const vulnerabilities: Vulnerability[] = [];

    // Try to fetch verified source from Etherscan API (if available)
    // For now, analyze bytecode patterns
    // In production, you'd integrate with Etherscan/Sourcify APIs

    // Run bytecode-based detectors
    // Since we need source code for full analysis, flag for review
    const evmDetectorNames = ["Reentrancy Vulnerability", "Weak Oracle Implementation"];
    const hasEVMDetectors = this.detectors.some(d => evmDetectorNames.includes(d.name));
    
    if (hasEVMDetectors) {
      vulnerabilities.push({
        id: `evm-contract-${address}-source-required`,
        title: "Source Code Required for Full Analysis",
        description: "Full vulnerability analysis requires verified source code. Bytecode-only analysis is limited.",
        severity: Severity.INFO,
        category: VulnerabilityCategory.LOGIC_ERROR,
        location: {
          contract: address
        },
        recommendation: "Verify contract source code on Etherscan/Sourcify for comprehensive analysis, or use bytecode decompilation tools."
      });
    }

    return this.buildResult("contract", address, vulnerabilities, {
      contractAddress: address,
      network: network,
      hasBytecode: bytecode !== "0x"
    });
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

