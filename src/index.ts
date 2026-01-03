/**
 * Xentinet Vulnerability Scanner
 * 
 * A comprehensive security scanning tool for smart contracts that supports:
 * - Contract address scanning (Solana & EVM)
 * - Git repository analysis
 * - Website URL scanning
 */

export { ContractScanner } from "./scanners/contract-scanner.js";
export { GitScanner } from "./scanners/git-scanner.js";
export { URLScanner } from "./scanners/url-scanner.js";
export { BaseDetector } from "./detectors/base-detector.js";
export { 
  MissingSignerCheckDetector, 
  MissingOwnershipCheckDetector,
  ReinitializationDetector,
  IntegerOverflowDetector,
  PDAAbuseDetector,
  ExternalProgramValidationDetector,
  AccountStructureValidationDetector
} from "./detectors/solana-detectors.js";
export { ReentrancyDetector, WeakOracleDetector } from "./detectors/evm-detectors.js";
export {
  SupplyChainDetector,
  XSSDetector,
  WalletIntegrationDetector
} from "./detectors/dapp-detectors.js";
export {
  CastTruncationDetector,
  CloseAccountDetector,
  DuplicatedAccountDetector,
  ErrorHandlingDetector,
  RoundingDetector
} from "./detectors/advanced-solana-detectors.js";
export * from "./types/vulnerability.js";
export type { GroupedVulnerability } from "./types/vulnerability.js";
export * from "./knowledge-base/vulnerability-registry.js";
export { VulnerabilityOrganizer } from "./organizer/vulnerability-organizer.js";
export { ExploitSimulator, ExploitabilityStatus } from "./simulator/exploit-simulator.js";
export type { ExploitAttempt } from "./simulator/exploit-simulator.js";
export { BugBountyReporter } from "./reporter/bug-bounty-reporter.js";
export { TestEnvironmentManager } from "./simulator/test-environment.js";
export { IdlFetcher } from "./idl/idl-fetcher.js";
export { fetchIdlFromRepo } from "./idl/idl-from-repo.js";
export { fetchIdlFromChain } from "./idl/idl-from-chain.js";
export { inferIdlFromBpf } from "./idl/idl-from-bpf.js";
export { generateIdlFromSource } from "./idl/idl-generator.js";
export { AccountInitializer } from "./exploit/account-initializer.js";
export type { InitializedAccounts } from "./exploit/account-initializer.js";
export { FuzzEngine } from "./exploit/fuzz-engine.js";
export { ExploitStrategies } from "./exploit/strategies.js";
export * from "./exploit/exploit-types.js";

