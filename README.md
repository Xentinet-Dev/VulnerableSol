# Xentinet Vulnerability Scanner

A comprehensive security scanning tool for smart contracts that supports multiple input sources: contract addresses, Git repositories, and website URLs.

## Features

- 🔍 **Contract Address Scanning**: Analyze on-chain contracts (Solana & EVM)
- 📦 **Git Repository Analysis**: Clone and scan entire repositories
- 🌐 **Website URL Scanning**: Extract contracts and repos from websites
- 🛡️ **Multi-Vulnerability Detection**: 
  - Solana account lifecycle vulnerabilities
  - Reentrancy attacks
  - Weak oracle implementations
  - Access control issues
  - And more...

## Installation

```bash
cd scanner
npm install
npm run build
```

## Usage

### Scan a Contract Address

**Solana:**
```bash
npm run scan contract <SOLANA_ADDRESS> -n solana -s https://api.mainnet-beta.solana.com
```

**EVM (Ethereum, Polygon, etc.):**
```bash
npm run scan contract <EVM_ADDRESS> -n ethereum -e https://eth.llamarpc.com
```

### Scan a Git Repository

```bash
npm run scan git https://github.com/user/repo.git -b main
```

### Scan a Website URL

```bash
npm run scan url https://example.com
```

This will:
- Extract contract addresses from the page
- Find repository links
- Analyze frontend code for security issues
- Scan all discovered contracts and repos

### Output Management

**Save Results to File:**
```bash
npm run scan contract <ADDRESS> -o scan-results.json
```

**Limit Number of Vulnerabilities Shown:**
```bash
npm run scan git <REPO_URL> -l 10  # Show only first 10 vulnerabilities
```

**Show Summary Only:**
```bash
npm run scan contract <ADDRESS> --summary-only  # Just statistics, no details
```

**Compact View (Titles Only):**
```bash
npm run scan git <REPO_URL> --compact  # Compact list format
```

**Combine Options:**
```bash
npm run scan git <REPO_URL> -l 5 --compact -o results.json
```

## Output Format

Results are displayed in the console with color-coded severity levels:
- 🔴 **CRITICAL**: Immediate security risk
- 🟣 **HIGH**: Significant security concern
- 🟡 **MEDIUM**: Moderate security issue
- 🔵 **LOW**: Minor security concern
- ⚪ **INFO**: Informational findings

**Default Behavior:**
- Shows first 20 vulnerabilities (sorted by severity)
- Full details for each vulnerability
- Suggests saving to file if many vulnerabilities found

**Each vulnerability includes:**
- Title and description
- Location (file, line, function)
- Recommended fix
- Code snippet (when available)

**Tips for Large Scans:**
- Use `--summary-only` for quick overview
- Use `-l <number>` to limit output
- Always use `-o <file>` to save full results for detailed analysis

## Architecture

```
scanner/
├── src/
│   ├── scanners/          # Scanner implementations
│   │   ├── contract-scanner.ts
│   │   ├── git-scanner.ts
│   │   └── url-scanner.ts
│   ├── detectors/         # Vulnerability detectors
│   │   ├── base-detector.ts
│   │   ├── solana-detectors.ts
│   │   └── evm-detectors.ts
│   ├── types/             # TypeScript types
│   │   └── vulnerability.ts
│   ├── cli.ts             # Command-line interface
│   └── index.ts           # Main exports
```

## Extending the Scanner

### Adding a New Detector

1. Create a new detector class extending `BaseDetector`:

```typescript
import { BaseDetector } from "./base-detector.js";
import { Vulnerability } from "../types/vulnerability.js";

export class MyCustomDetector extends BaseDetector {
  name = "My Custom Vulnerability";
  description = "Detects my custom vulnerability pattern";

  isApplicable(filePath: string): boolean {
    return filePath.endsWith(".sol") || filePath.endsWith(".rs");
  }

  async detect(content: string, context?: any): Promise<Vulnerability[]> {
    // Your detection logic here
    return [];
  }
}
```

2. Register it in the scanner:

```typescript
this.detectors.push(new MyCustomDetector());
```

## Configuration

### RPC Endpoints

Default RPC endpoints are provided, but you can specify custom ones:

- Solana: `-s https://your-solana-rpc.com`
- EVM: `-e https://your-evm-rpc.com`

### Temporary Directory

Git scanner uses `./.scan-temp` by default. Ensure you have write permissions.

## Limitations

- **Bytecode Analysis**: Full analysis requires verified source code. Bytecode-only analysis is limited.
- **Rate Limiting**: Be mindful of RPC rate limits when scanning multiple contracts.
- **Repository Size**: Large repositories may take significant time to clone and scan.

## Examples & Use Cases

See `SCAN_EXAMPLES.md` for comprehensive examples of:
- Real-world protocols to scan
- Testing scenarios
- Complete audit workflows
- Priority scanning checklist

## Contributing

This scanner integrates with Xentinet's vulnerability detection patterns documented in:
- `Solana Account Lifecycle Vulnerabilities_ Detection & Mitigation.md`
- `1. Reentrancy Vulnerability.md`
- And other vulnerability documentation files

## License

MIT

