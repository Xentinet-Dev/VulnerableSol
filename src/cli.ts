#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { ContractScanner } from "./scanners/contract-scanner.js";
import { GitScanner } from "./scanners/git-scanner.js";
import { URLScanner } from "./scanners/url-scanner.js";
import { ScanResult, Severity } from "./types/vulnerability.js";
import * as fs from "fs/promises";
import * as path from "path";

const program = new Command();

program
  .name("xentinet-scanner")
  .description("Xentinet Vulnerability Scanner - Multi-source security analysis tool")
  .version("1.0.0");

// Contract address scanning
program
  .command("contract")
  .description("Scan a contract address")
  .argument("<address>", "Contract address to scan")
  .option("-n, --network <network>", "Network (solana, ethereum, polygon, etc.)", "ethereum")
  .option("-s, --solana-rpc <url>", "Solana RPC URL", "https://api.mainnet-beta.solana.com")
  .option("-e, --evm-rpc <url>", "EVM RPC URL", "https://eth.llamarpc.com")
  .option("-o, --output <file>", "Output file for results (JSON)")
  .option("-l, --limit <number>", "Limit number of vulnerabilities shown (default: 20)", "20")
  .option("--summary-only", "Show only summary statistics")
  .option("--compact", "Show compact view (titles only)")
  .action(async (address, options) => {
    console.log(chalk.blue(`\n🔍 Scanning contract: ${address}`));
    console.log(chalk.gray(`Network: ${options.network}\n`));

    try {
      const scanner = new ContractScanner(options.solanaRpc, options.evmRpc);
      
      let result: ScanResult;
      if (options.network === "solana") {
        result = await scanner.scanSolanaContract(address);
      } else {
        result = await scanner.scanEVMContract(address, options.network);
      }

      printResults(result, {
        limit: parseInt(options.limit) || 20,
        summaryOnly: options.summaryOnly || false,
        compact: options.compact || false
      });

      if (options.output) {
        await saveResults(result, options.output);
      } else if (result.vulnerabilities.length > 0) {
        console.log(chalk.yellow(`\n💡 Tip: Use -o <file> to save full results to JSON`));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`\n❌ Error: ${message}`));
      process.exit(1);
    }
  });

// Git repository scanning
program
  .command("git")
  .description("Scan a Git repository")
  .argument("<url>", "Git repository URL")
  .option("-b, --branch <branch>", "Branch to scan", "main")
  .option("-o, --output <file>", "Output file for results (JSON)")
  .option("-l, --limit <number>", "Limit number of vulnerabilities shown (default: 20)", "20")
  .option("--summary-only", "Show only summary statistics")
  .option("--compact", "Show compact view (titles only)")
  .action(async (url, options) => {
    console.log(chalk.blue(`\n🔍 Scanning repository: ${url}`));
    console.log(chalk.gray(`Branch: ${options.branch}\n`));

    try {
      const scanner = new GitScanner();
      const result = await scanner.scanRepository(url, options.branch);

      printResults(result, {
        limit: parseInt(options.limit) || 20,
        summaryOnly: options.summaryOnly || false,
        compact: options.compact || false
      });

      if (options.output) {
        await saveResults(result, options.output);
      } else if (result.vulnerabilities.length > 0) {
        console.log(chalk.yellow(`\n💡 Tip: Use -o <file> to save full results to JSON`));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`\n❌ Error: ${message}`));
      process.exit(1);
    }
  });

// URL scanning
program
  .command("url")
  .description("Scan a website URL for contracts and repositories")
  .argument("<url>", "Website URL to scan")
  .option("-s, --solana-rpc <url>", "Solana RPC URL", "https://api.mainnet-beta.solana.com")
  .option("-e, --evm-rpc <url>", "EVM RPC URL", "https://eth.llamarpc.com")
  .option("-o, --output <file>", "Output file for results (JSON)")
  .option("-l, --limit <number>", "Limit number of vulnerabilities shown per result (default: 20)", "20")
  .option("--summary-only", "Show only summary statistics")
  .option("--compact", "Show compact view (titles only)")
  .action(async (url, options) => {
    console.log(chalk.blue(`\n🔍 Scanning URL: ${url}\n`));

    try {
      const scanner = new URLScanner(options.solanaRpc, options.evmRpc);
      const results = await scanner.scanURL(url);

      console.log(chalk.green(`\n✅ Found ${results.length} scan result(s)\n`));

      for (const result of results) {
        printResults(result, {
          limit: parseInt(options.limit) || 20,
          summaryOnly: options.summaryOnly || false,
          compact: options.compact || false
        });
        console.log();
      }

      if (options.output) {
        await saveResults(results, options.output);
      } else {
        const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
        if (totalVulns > 0) {
          console.log(chalk.yellow(`\n💡 Tip: Use -o <file> to save full results to JSON`));
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`\n❌ Error: ${message}`));
      process.exit(1);
    }
  });

interface PrintOptions {
  limit?: number;
  summaryOnly?: boolean;
  compact?: boolean;
}

function printResults(result: ScanResult, options: PrintOptions = {}): void {
  const { limit = 20, summaryOnly = false, compact = false } = options;

  console.log(chalk.bold(`\n📊 Scan Results for: ${result.target}`));
  console.log(chalk.gray(`Type: ${result.targetType} | Time: ${result.timestamp.toISOString()}\n`));

  // Summary
  const { summary } = result;
  console.log(chalk.bold("Summary:"));
  console.log(`  Total: ${summary.total}`);
  console.log(`  ${chalk.red(`Critical: ${summary.critical}`)}`);
  console.log(`  ${chalk.magenta(`High: ${summary.high}`)}`);
  console.log(`  ${chalk.yellow(`Medium: ${summary.medium}`)}`);
  console.log(`  ${chalk.blue(`Low: ${summary.low}`)}`);
  console.log(`  ${chalk.gray(`Info: ${summary.info}`)}`);

  if (summaryOnly) {
    if (result.vulnerabilities.length > 0) {
      console.log(chalk.yellow(`\n⚠️  ${result.vulnerabilities.length} vulnerabilities found (use -o <file> to see full details)`));
    } else {
      console.log(chalk.green("\n✅ No vulnerabilities found!"));
    }
    return;
  }

  if (result.vulnerabilities.length > 0) {
    // Sort vulnerabilities by severity (Critical first)
    const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];
    const sortedVulns = [...result.vulnerabilities].sort((a, b) => {
      return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    });

    // Limit the number shown
    const vulnsToShow = sortedVulns.slice(0, limit);
    const remaining = result.vulnerabilities.length - vulnsToShow.length;

    console.log(chalk.bold(`\n🔴 Vulnerabilities (showing ${vulnsToShow.length} of ${result.vulnerabilities.length}):\n`));

    // Group by severity
    const bySeverity = {
      [Severity.CRITICAL]: vulnsToShow.filter(v => v.severity === Severity.CRITICAL),
      [Severity.HIGH]: vulnsToShow.filter(v => v.severity === Severity.HIGH),
      [Severity.MEDIUM]: vulnsToShow.filter(v => v.severity === Severity.MEDIUM),
      [Severity.LOW]: vulnsToShow.filter(v => v.severity === Severity.LOW),
      [Severity.INFO]: vulnsToShow.filter(v => v.severity === Severity.INFO)
    };

    for (const [severity, vulns] of Object.entries(bySeverity)) {
      if (vulns.length === 0) continue;

      const color = severity === Severity.CRITICAL ? chalk.red :
                   severity === Severity.HIGH ? chalk.magenta :
                   severity === Severity.MEDIUM ? chalk.yellow :
                   severity === Severity.LOW ? chalk.blue : chalk.gray;

      console.log(color.bold(`\n${severity} (${vulns.length}):`));

      for (const vuln of vulns) {
        if (compact) {
          // Compact view: just title and location
          const location = vuln.location.file 
            ? `${vuln.location.file}${vuln.location.line ? `:${vuln.location.line}` : ""}`
            : "";
          console.log(color(`  • ${vuln.title}${location ? ` ${chalk.gray(`(${location})`)}` : ""}`));
        } else {
          // Full view
          console.log(color(`  • ${vuln.title}`));
          console.log(chalk.gray(`    ${vuln.description}`));
          if (vuln.location.file || vuln.location.line) {
            console.log(chalk.gray(`    Location: ${vuln.location.file || ""}${vuln.location.line ? `:${vuln.location.line}` : ""}`));
          }
          console.log(chalk.cyan(`    Fix: ${vuln.recommendation}`));
          console.log();
        }
      }
    }

    if (remaining > 0) {
      console.log(chalk.yellow(`\n⚠️  ... and ${remaining} more vulnerability/vulnerabilities (use -l <number> to show more or -o <file> for full JSON)`));
    }
  } else {
    console.log(chalk.green("\n✅ No vulnerabilities found!"));
  }
}

async function saveResults(result: ScanResult | ScanResult[], filePath: string): Promise<void> {
  const data = JSON.stringify(result, null, 2);
  await fs.writeFile(filePath, data, "utf-8");
  console.log(chalk.green(`\n💾 Results saved to: ${filePath}`));
}

program.parse();

