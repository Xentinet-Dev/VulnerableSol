import axios from "axios";
import * as cheerio from "cheerio";
import { ScanResult, Vulnerability, Severity, VulnerabilityCategory } from "../types/vulnerability.js";
import { ContractScanner } from "./contract-scanner.js";
import { GitScanner } from "./git-scanner.js";
import { BaseDetector } from "../detectors/base-detector.js";

/**
 * Scanner for website URLs
 * Extracts contract addresses and repository links
 */
export class URLScanner {
  private contractScanner: ContractScanner;
  private gitScanner: GitScanner;
  private dappDetectors: BaseDetector[] = [];

  constructor(solanaRpcUrl?: string, evmRpcUrl?: string) {
    this.contractScanner = new ContractScanner(solanaRpcUrl, evmRpcUrl);
    this.gitScanner = new GitScanner();
    // URL scanner uses contract and git scanners which have their own detectors
  }

  private async initializeDappDetectors(): Promise<void> {
    if (this.dappDetectors.length > 0) return; // Already initialized

    const {
      XSSDetector,
      WalletIntegrationDetector
    } = await import("../detectors/dapp-detectors.js");

    this.dappDetectors = [
      new XSSDetector(),
      new WalletIntegrationDetector()
    ];
  }

  /**
   * Scan a website URL for contract addresses and repository links
   */
  async scanURL(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    
    try {
      // Fetch the webpage
      const response = await axios.get(url, {
        timeout: 10000,
        headers: {
          "User-Agent": "Mozilla/5.0 (Xentinet Security Scanner)"
        }
      });

      const $ = cheerio.load(response.data);
      const html = response.data;

      // Extract contract addresses
      const contractAddresses = this.extractContractAddresses(html, $);
      
      // Extract repository links
      const repoLinks = this.extractRepositoryLinks(html, $);

      // Scan found contracts
      for (const address of contractAddresses.solana) {
        try {
          const result = await this.contractScanner.scanSolanaContract(address);
          results.push(result);
        } catch (error) {
          console.error(`Error scanning Solana contract ${address}:`, error);
        }
      }

      for (const address of contractAddresses.evm) {
        try {
          const result = await this.contractScanner.scanEVMContract(address);
          results.push(result);
        } catch (error) {
          console.error(`Error scanning EVM contract ${address}:`, error);
        }
      }

      // Scan found repositories
      for (const repoUrl of repoLinks) {
        try {
          const result = await this.gitScanner.scanRepository(repoUrl);
          results.push(result);
        } catch (error) {
          console.error(`Error scanning repository ${repoUrl}:`, error);
        }
      }

      // Analyze frontend code for security issues
      await this.initializeDappDetectors();
      const frontendVulns = await this.analyzeFrontend(html, url);
      if (frontendVulns.length > 0) {
        results.push({
          target: url,
          targetType: "url",
          timestamp: new Date(),
          vulnerabilities: frontendVulns,
          summary: {
            total: frontendVulns.length,
            critical: frontendVulns.filter(v => v.severity === Severity.CRITICAL).length,
            high: frontendVulns.filter(v => v.severity === Severity.HIGH).length,
            medium: frontendVulns.filter(v => v.severity === Severity.MEDIUM).length,
            low: frontendVulns.filter(v => v.severity === Severity.LOW).length,
            info: frontendVulns.filter(v => v.severity === Severity.INFO).length
          },
          metadata: {
            url: url,
            contractsFound: contractAddresses.solana.length + contractAddresses.evm.length,
            repositoriesFound: repoLinks.length
          }
        });
      }

    } catch (error) {
      throw new Error(`Failed to scan URL ${url}: ${error}`);
    }

    return results;
  }

  /**
   * Extract contract addresses from HTML
   */
  private extractContractAddresses(html: string, $: cheerio.CheerioAPI): {
    solana: string[];
    evm: string[];
  } {
    const solana: string[] = [];
    const evm: string[] = [];

    // Solana addresses are base58 encoded, typically 32-44 characters
    const solanaPattern = /[1-9A-HJ-NP-Za-km-z]{32,44}/g;
    const solanaMatches = html.match(solanaPattern) || [];
    
    // Filter for likely Solana addresses (common patterns)
    for (const match of solanaMatches) {
      if (match.length >= 32 && match.length <= 44) {
        // Additional validation: Solana addresses don't contain 0, O, I, l
        if (!/[0OIl]/.test(match)) {
          solana.push(match);
        }
      }
    }

    // EVM addresses are 0x followed by 40 hex characters
    const evmPattern = /0x[a-fA-F0-9]{40}/g;
    const evmMatches = html.match(evmPattern) || [];
    evm.push(...evmMatches);

    // Also check data attributes and meta tags
    $("[data-contract], [data-address], [data-program]").each((_, el) => {
      const address = $(el).attr("data-contract") || 
                     $(el).attr("data-address") || 
                     $(el).attr("data-program");
      if (address) {
        if (address.startsWith("0x")) {
          evm.push(address);
        } else if (address.length >= 32 && address.length <= 44) {
          solana.push(address);
        }
      }
    });

    return {
      solana: [...new Set(solana)],
      evm: [...new Set(evm)]
    };
  }

  /**
   * Extract repository links from HTML
   */
  private extractRepositoryLinks(html: string, $: cheerio.CheerioAPI): string[] {
    const repos: string[] = [];

    // Find GitHub, GitLab, Bitbucket links
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href) {
        if (href.includes("github.com") || 
            href.includes("gitlab.com") || 
            href.includes("bitbucket.org")) {
          // Normalize to .git URL
          let repoUrl = href;
          if (!repoUrl.endsWith(".git")) {
            repoUrl = repoUrl.replace(/\/$/, "") + ".git";
          }
          if (!repoUrl.startsWith("http")) {
            repoUrl = "https://" + repoUrl.replace(/^\/+/, "");
          }
          repos.push(repoUrl);
        }
      }
    });

    return [...new Set(repos)];
  }

  /**
   * Analyze frontend code for security issues
   */
  private async analyzeFrontend(html: string, url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Check for exposed private keys or API keys
    const privateKeyPattern = /(private[_-]?key|secret[_-]?key|api[_-]?key)\s*[:=]\s*["']([^"']+)["']/gi;
    const matches = html.matchAll(privateKeyPattern);
    for (const match of matches) {
      vulnerabilities.push({
        id: `exposed-key-${match.index}`,
        title: "Exposed Private Key or API Key",
        description: `Potential private key or API key found in frontend code: ${match[2].substring(0, 20)}...`,
        severity: Severity.CRITICAL,
        category: VulnerabilityCategory.ACCESS_CONTROL,
        location: {
          file: url
        },
        recommendation: "Never expose private keys or API keys in frontend code. Use environment variables and backend services for sensitive operations."
      });
    }

    // Run dApp detectors on HTML content
    for (const detector of this.dappDetectors) {
      if (detector.isApplicable(url) || detector.isApplicable("inline.html")) {
        try {
          const detectorVulns = await detector.detect(html, {
            filePath: url,
            isHTML: true
          });
          vulnerabilities.push(...detectorVulns);
        } catch (error) {
          // Continue with other detectors if one fails
          console.warn(`Detector ${detector.name} failed:`, error);
        }
      }
    }

    // Check for insecure wallet connection patterns (legacy check, also covered by WalletIntegrationDetector)
    if (html.includes("window.ethereum") || html.includes("window.solana")) {
      // Check if there's proper error handling
      if (!html.includes("try") || !html.includes("catch")) {
        // Only add if WalletIntegrationDetector didn't already catch it
        const alreadyReported = vulnerabilities.some(v => 
          v.title === "Wallet Integration Flaws" || v.title === "Insecure Wallet Connection"
        );
        if (!alreadyReported) {
          vulnerabilities.push({
            id: `insecure-wallet-connection-${url}`,
            title: "Insecure Wallet Connection",
            description: "Wallet connection detected without proper error handling. This could lead to user fund loss.",
            severity: Severity.MEDIUM,
            category: VulnerabilityCategory.ACCESS_CONTROL,
            location: {
              file: url
            },
            recommendation: "Implement proper error handling and user confirmation for all wallet operations. Validate transaction parameters before submission."
          });
        }
      }
    }

    return vulnerabilities;
  }
}

