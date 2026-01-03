#!/usr/bin/env node

/**
 * Exploit Simulator CLI
 * 
 * Command-line interface for the exploit simulator pipeline
 */

import { Command } from "commander";
import chalk from "chalk";
import * as fs from "fs/promises";
import { ContractScanner } from "./scanners/contract-scanner.js";
import { GitScanner } from "./scanners/git-scanner.js";
import { VulnerabilityOrganizer } from "./organizer/vulnerability-organizer.js";
import { ExploitSimulator, ExploitabilityStatus } from "./simulator/exploit-simulator.js";
import { BugBountyReporter } from "./reporter/bug-bounty-reporter.js";
import { ScanResult } from "./types/vulnerability.js";

const program = new Command();

program
  .name("xentinet-simulator")
  .description("Xentinet Exploit Simulator - Verify exploitability of vulnerabilities")
  .version("1.0.0");

// Simulate exploit from scan results
program
  .command("simulate")
  .description("Simulate exploits for vulnerabilities found in scan")
  .argument("<scan-results>", "Path to scan results JSON file")
  .option("-o, --output <file>", "Output file for simulation results")
  .option("-r, --report <file>", "Generate bug bounty report")
  .option("-f, --filter <severity>", "Filter by severity (CRITICAL, HIGH, MEDIUM)", "CRITICAL")
  .action(async (scanResultsPath, options) => {
    console.log(chalk.blue(`\n🔬 Loading scan results from: ${scanResultsPath}\n`));

    try {
      // Load scan results
      const scanData = await fs.readFile(scanResultsPath, "utf-8");
      const scanResults: ScanResult[] = JSON.parse(scanData);

      // Organize vulnerabilities
      const organizer = new VulnerabilityOrganizer();
      const grouped = organizer.organize(scanResults);

      console.log(chalk.bold("📊 Vulnerability Summary:"));
      console.log(`  Total: ${grouped.summary.total}`);
      console.log(`  Critical: ${chalk.red(grouped.summary.critical.toString())}`);
      console.log(`  High: ${chalk.magenta(grouped.summary.high.toString())}`);
      console.log(`  Medium: ${chalk.yellow(grouped.summary.medium.toString())}`);
      console.log(`  Unique Files: ${grouped.summary.uniqueFiles}`);
      console.log(`  Attack Surfaces: ${grouped.summary.attackSurfaces}\n`);

      // Filter by severity
      const vulnerabilitiesToSimulate = 
        options.filter === "CRITICAL" ? grouped.byCategory.CRITICAL :
        options.filter === "HIGH" ? [...grouped.byCategory.CRITICAL, ...grouped.byCategory.HIGH] :
        grouped.byCategory.CRITICAL;

      if (vulnerabilitiesToSimulate.length === 0) {
        console.log(chalk.yellow("No vulnerabilities found matching filter criteria."));
        return;
      }

      console.log(chalk.blue(`\n🔬 Simulating ${vulnerabilitiesToSimulate.length} vulnerabilities...\n`));

      // Simulate exploits
      const simulator = new ExploitSimulator();
      const simulationResults = [];

      for (const vuln of vulnerabilitiesToSimulate) {
        console.log(chalk.gray(`\n--- Simulating: ${vuln.title} ---`));
        console.log(chalk.gray(`   ${vuln.location.file}:${vuln.location.line}`));

        const exploitAttempt = await simulator.simulateExploit(vuln);
        
        // Display results
        const statusColor = 
          exploitAttempt.status === ExploitabilityStatus.DEFINITELY_EXPLOITABLE ? chalk.red :
          exploitAttempt.status === ExploitabilityStatus.POTENTIALLY_EXPLOITABLE ? chalk.magenta :
          exploitAttempt.status === ExploitabilityStatus.FALSE_POSITIVE ? chalk.green :
          chalk.yellow;

        console.log(statusColor(`\n   Status: ${exploitAttempt.status}`));
        
        if (exploitAttempt.canDrainFunds) {
          console.log(chalk.red("   ⚠️  CAN DRAIN FUNDS"));
        }
        if (exploitAttempt.canManipulateState) {
          console.log(chalk.yellow("   ⚠️  CAN MANIPULATE STATE"));
        }

        simulationResults.push({
          vulnerability: vuln,
          exploitAttempt,
          timestamp: new Date()
        });
      }

      // Save results
      if (options.output) {
        await fs.writeFile(options.output, JSON.stringify(simulationResults, null, 2));
        console.log(chalk.green(`\n💾 Simulation results saved to: ${options.output}`));
      }

      // Generate bug bounty reports for exploitable vulnerabilities
      const exploitable = simulationResults.filter(r =>
        r.exploitAttempt.status === ExploitabilityStatus.DEFINITELY_EXPLOITABLE ||
        r.exploitAttempt.status === ExploitabilityStatus.POTENTIALLY_EXPLOITABLE
      );

      if (exploitable.length > 0 && options.report) {
        console.log(chalk.blue(`\n📝 Generating bug bounty reports for ${exploitable.length} exploitable vulnerabilities...`));
        
        const reporter = new BugBountyReporter();
        const reports = [];

        for (const result of exploitable) {
          const report = reporter.generateReport(
            result.vulnerability,
            result.exploitAttempt
          );
          reports.push(report);
        }

        // Save markdown report
        const markdownReport = reports.map(r => 
          reporter.generateMarkdownReport(r)
        ).join("\n\n---\n\n");

        await fs.writeFile(options.report, markdownReport);
        console.log(chalk.green(`💾 Bug bounty report saved to: ${options.report}`));
      }

      // Summary
      const definitelyExploitable = simulationResults.filter(r =>
        r.exploitAttempt.status === ExploitabilityStatus.DEFINITELY_EXPLOITABLE
      ).length;

      const potentiallyExploitable = simulationResults.filter(r =>
        r.exploitAttempt.status === ExploitabilityStatus.POTENTIALLY_EXPLOITABLE
      ).length;

      console.log(chalk.bold("\n📊 Simulation Summary:"));
      console.log(`  Definitely Exploitable: ${chalk.red(definitelyExploitable.toString())}`);
      console.log(`  Potentially Exploitable: ${chalk.magenta(potentiallyExploitable.toString())}`);
      console.log(`  Not Exploitable: ${chalk.green((simulationResults.length - definitelyExploitable - potentiallyExploitable).toString())}`);

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`\n❌ Error: ${message}`));
      process.exit(1);
    }
  });

// Organize vulnerabilities
program
  .command("organize")
  .description("Organize vulnerabilities from scan results")
  .argument("<scan-results>", "Path to scan results JSON file")
  .option("-o, --output <file>", "Output file for organized results")
  .action(async (scanResultsPath, options) => {
    try {
      const scanData = await fs.readFile(scanResultsPath, "utf-8");
      const scanResults: ScanResult[] = JSON.parse(scanData);

      const organizer = new VulnerabilityOrganizer();
      const grouped = organizer.organize(scanResults);

      // Display organized view
      console.log(chalk.bold("\n📊 Organized Vulnerabilities:\n"));

      console.log(chalk.red.bold("CRITICAL:"));
      for (const vuln of grouped.byCategory.CRITICAL) {
        console.log(`  • ${vuln.title} - ${vuln.location.file}:${vuln.location.line}`);
      }

      console.log(chalk.magenta.bold("\nHIGH:"));
      for (const vuln of grouped.byCategory.HIGH) {
        console.log(`  • ${vuln.title} - ${vuln.location.file}:${vuln.location.line}`);
      }

      console.log(chalk.yellow.bold("\nMEDIUM:"));
      for (const vuln of grouped.byCategory.MEDIUM) {
        console.log(`  • ${vuln.title} - ${vuln.location.file}:${vuln.location.line}`);
      }

      console.log(chalk.bold("\n📁 By File:"));
      for (const [file, data] of Object.entries(grouped.byFile)) {
        console.log(`  ${file}:`);
        console.log(`    Vulnerabilities: ${data.vulnerabilities.length}`);
        console.log(`    Critical: ${data.criticalCount}, High: ${data.highCount}`);
        console.log(`    Attack Surfaces: ${data.attackSurfaces.join(", ")}`);
      }

      console.log(chalk.bold("\n🎯 By Attack Surface:"));
      console.log(`  Account Forgery: ${grouped.byAttackSurface.accountForgery.length}`);
      console.log(`  Program Invocation: ${grouped.byAttackSurface.programInvocation.length}`);
      console.log(`  Arithmetic: ${grouped.byAttackSurface.arithmetic.length}`);
      console.log(`  Memory Truncation: ${grouped.byAttackSurface.memoryTruncation.length}`);
      console.log(`  Error Handling: ${grouped.byAttackSurface.errorHandling.length}`);
      console.log(`  Access Control: ${grouped.byAttackSurface.accessControl.length}`);

      if (options.output) {
        await fs.writeFile(options.output, JSON.stringify(grouped, null, 2));
        console.log(chalk.green(`\n💾 Organized results saved to: ${options.output}`));
      }

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`\n❌ Error: ${message}`));
      process.exit(1);
    }
  });

program.parse();

