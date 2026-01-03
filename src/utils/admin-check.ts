/**
 * Admin Privilege Detection for Windows
 * 
 * Checks if the current process is running with administrator privileges
 */

import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

/**
 * Check if the current process is running with administrator privileges
 * @returns true if running as admin, false otherwise
 */
export async function isRunningAsAdmin(): Promise<boolean> {
  if (process.platform !== "win32") {
    // On non-Windows, assume we have necessary privileges
    return true;
  }

  try {
    // Use net session to check admin privileges (works on Windows)
    // If it succeeds, we're admin; if it fails, we're not
    await execAsync("net session");
    return true;
  } catch {
    return false;
  }
}

/**
 * Get a user-friendly message about admin requirements
 */
export function getAdminRequirementMessage(): string {
  return `
⚠️  ADMINISTRATOR PRIVILEGES REQUIRED

The Solana test validator requires administrator privileges on Windows.

OPTIONS:
1. Run Cursor as Administrator (Recommended)
   - Right-click Cursor → "Run as administrator"
   - All processes will inherit admin privileges

2. Start Validator Manually (Current Method)
   - Run: START_VALIDATOR_AS_ADMIN.ps1
   - Or: solana-test-validator --reset (in admin PowerShell)

3. Use Alternative Test Environment
   - Connect to devnet/mainnet (no admin needed)
   - Note: Real funds required for testing

Current Status: ${process.platform === "win32" ? "Windows detected" : "Non-Windows OS"}
`;
}


