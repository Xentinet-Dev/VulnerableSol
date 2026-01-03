/**
 * Toolchain Helper
 * 
 * Provides utilities for managing Rust toolchains to prevent Anchor
 * from activating the Solana toolchain (1.75.0-dev) during builds.
 */

import { execSync } from "child_process";
import * as path from "path";

export class ToolchainHelper {
  /**
   * Ensure stable Rust toolchain is active and Solana toolchain is removed
   * This should be called before any build operation to prevent Anchor
   * from activating the Solana toolchain (1.75.0-dev)
   */
  static ensureStableToolchain(): void {
    try {
      // Remove Solana toolchain if it exists
      try {
        execSync("rustup toolchain uninstall solana", { 
          stdio: "ignore",
          timeout: 5000
        });
        console.log("[+] Removed Solana toolchain");
      } catch (e) {
        // Ignore if not installed
      }

      // Set stable as default
      execSync("rustup default stable", { 
        stdio: "ignore",
        timeout: 5000
      });
      
      // Set environment variables
      process.env.RUSTUP_TOOLCHAIN = "stable";
      process.env.CARGO_BUILD_SBF_USE_SYSTEM_RUST = "true";
      
      // Filter PATH to exclude Solana toolchain locations
      const currentPath = process.env.PATH || "";
      const paths = currentPath.split(path.delimiter);
      const filteredPaths = paths.filter(
        (p) => !p.includes(".local/share/solana/install")
      );
      process.env.PATH = filteredPaths.join(path.delimiter);
      
      console.log("[+] Stable toolchain ensured, Solana toolchain removed from PATH");
    } catch (error: any) {
      console.log(`[!] Toolchain management warning: ${error.message}`);
      // Continue anyway - try to set environment variables at minimum
      process.env.RUSTUP_TOOLCHAIN = "stable";
      process.env.CARGO_BUILD_SBF_USE_SYSTEM_RUST = "true";
    }
  }

  /**
   * Get build environment with stable toolchain settings
   */
  static getStableBuildEnv(): NodeJS.ProcessEnv {
    const env = { ...process.env };
    env.RUSTUP_TOOLCHAIN = "stable";
    env.CARGO_BUILD_SBF_USE_SYSTEM_RUST = "true";
    
    // Filter PATH
    const currentPath = env.PATH || "";
    const paths = currentPath.split(path.delimiter);
    env.PATH = paths
      .filter((p) => !p.includes(".local/share/solana/install"))
      .join(path.delimiter);
    
    return env;
  }
}
