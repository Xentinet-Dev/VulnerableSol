#!/usr/bin/env node

/**
 * REST API Server for Xentinet Vulnerability Scanner
 * 
 * Run with: npm run api-server
 * Or: node dist/api-server.js
 */

console.log("🚀 Starting API Server initialization...");

import express, { Request, Response } from 'express';
import cors from 'cors';
import {
  ContractScanner,
  GitScanner,
  URLScanner,
  VulnerabilityOrganizer,
  ExploitSimulator,
  BugBountyReporter,
  ScanResult,
  Vulnerability,
  Severity
} from './index.js';
import type { ExploitAttempt } from './simulator/exploit-simulator.js';

console.log("✅ Imports loaded successfully");

const app = express();

// CORS configuration - allow all origins for development
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
}));

app.use(express.json());

// Handle Chrome DevTools .well-known requests (non-critical)
app.get('/.well-known/*', (req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

console.log("✅ Express app configured");

// Initialize scanners (singletons) with error handling
let contractScanner: ContractScanner;
let gitScanner: GitScanner;
let urlScanner: URLScanner;
let organizer: VulnerabilityOrganizer;
let simulator: ExploitSimulator;
let reporter: BugBountyReporter;

try {
  console.log("📦 Initializing scanners...");
  contractScanner = new ContractScanner(
    process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com',
    process.env.EVM_RPC || 'https://eth.llamarpc.com'
  );
  gitScanner = new GitScanner();
  urlScanner = new URLScanner(
    process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com',
    process.env.EVM_RPC || 'https://eth.llamarpc.com'
  );
  organizer = new VulnerabilityOrganizer();
  simulator = new ExploitSimulator(process.env.TEST_VALIDATOR_URL || 'http://localhost:8899');
  reporter = new BugBountyReporter();
  console.log("✅ All scanners initialized successfully");
} catch (error) {
  console.error("❌ Failed to initialize scanners:", error);
  process.exit(1);
}

// Health check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Docker status check
app.get('/api/docker/status', async (req: Request, res: Response) => {
  try {
    const { DockerBuilder } = await import('./utils/docker-builder.js');
    const dockerBuilder = new DockerBuilder();
    
    const dockerAvailable = await dockerBuilder.isDockerAvailable();
    const containersRunning = await dockerBuilder.areContainersRunning();
    
    res.json({
      dockerAvailable,
      containersRunning,
      containerName: 'anchor-build-env',
      status: dockerAvailable && containersRunning ? 'ready' : 'not_ready',
      message: dockerAvailable && containersRunning 
        ? 'Docker is ready - builds will use containerized environment'
        : dockerAvailable 
          ? 'Docker is available but containers are not running. Run: docker-compose up -d'
          : 'Docker is not available - will use native builds'
    });
  } catch (error: any) {
    res.status(500).json({
      dockerAvailable: false,
      containersRunning: false,
      status: 'error',
      error: error.message
    });
  }
});

// Scan Solana Contract
app.post('/api/scan/contract/solana', async (req: Request, res: Response) => {
  try {
    const { programId, deduplicate = true } = req.body;
    
    if (!programId) {
      return res.status(400).json({ error: 'programId is required' });
    }

    const result = await contractScanner.scanSolanaContract(programId);
    
    // Deduplicate if requested
    if (deduplicate) {
      const grouped = organizer.deduplicate(result.vulnerabilities);
      res.json({
        ...result,
        vulnerabilities: grouped.map(g => g.representative), // Return representatives
        grouped: grouped, // Include full grouped data
        summary: {
          ...result.summary,
          unique: grouped.length,
          total: result.vulnerabilities.length
        }
      });
    } else {
      res.json(result);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Solana contract scan error:', message);
    res.status(500).json({ error: message });
  }
});

// Scan EVM Contract
app.post('/api/scan/contract/evm', async (req: Request, res: Response) => {
  try {
    const { address, network = 'ethereum' } = req.body;
    
    if (!address) {
      return res.status(400).json({ error: 'address is required' });
    }

    const result = await contractScanner.scanEVMContract(address, network);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('EVM contract scan error:', message);
    res.status(500).json({ error: message });
  }
});

// Scan Git Repository
app.post('/api/scan/git', async (req: Request, res: Response) => {
  try {
    // Default enableTesting to true to preserve repositories for simulation
    // Users can set enableTesting=false explicitly if they want immediate cleanup
    const { url, branch, deduplicate = true, enableTesting = true } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'url is required' });
    }

    // Handle repository preservation for testing
    if (enableTesting) {
      console.warn(`🚨 SECURITY WARNING: Repository preservation enabled for testing`);
      console.warn(`🚨 This keeps potentially vulnerable code on disk after scanning`);
      console.warn(`🚨 Only use this in controlled testing environments`);
      console.warn(`🚨 Call POST /api/cleanup-repos when testing is complete`);
    }

    const result = await gitScanner.scanRepository(url, branch, enableTesting);
    
    // Store repository path in result metadata for simulator access
    if (result.metadata && result.metadata.repositoryPath) {
      // Ensure all vulnerabilities have the repository path in metadata
      for (const vuln of result.vulnerabilities) {
        if (!vuln.metadata) {
          vuln.metadata = {};
        }
        if (!vuln.metadata.repositoryPath) {
          vuln.metadata.repositoryPath = result.metadata.repositoryPath;
        }
        if (!vuln.metadata.repositoryUrl) {
          vuln.metadata.repositoryUrl = url;
        }
      }
    }
    
    // Deduplicate if requested
    if (deduplicate) {
      const grouped = organizer.deduplicate(result.vulnerabilities);
      res.json({
        ...result,
        vulnerabilities: grouped.map(g => g.representative), // Return representatives
        grouped: grouped, // Include full grouped data
        summary: {
          ...result.summary,
          unique: grouped.length,
          total: result.vulnerabilities.length
        }
      });
    } else {
      res.json(result);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Git scan error:', message);
    res.status(500).json({ error: message });
  }
});

// Scan URL
app.post('/api/scan/url', async (req: Request, res: Response) => {
  try {
    const { url, deduplicate = true } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'url is required' });
    }

    const results = await urlScanner.scanURL(url);
    
    // Flatten all vulnerabilities from all results
    const allVulnerabilities: Vulnerability[] = [];
    for (const result of results) {
      allVulnerabilities.push(...result.vulnerabilities);
    }
    
    // Deduplicate if requested
    if (deduplicate) {
      const grouped = organizer.deduplicate(allVulnerabilities);
      res.json({
        results: results.map(r => ({
          ...r,
          vulnerabilities: r.vulnerabilities.filter(v => 
            grouped.some(g => g.instances.includes(v))
          )
        })),
        vulnerabilities: grouped.map(g => g.representative),
        grouped: grouped,
        summary: {
          total: allVulnerabilities.length,
          unique: grouped.length,
          critical: grouped.filter(g => g.representative.severity === Severity.CRITICAL).length,
          high: grouped.filter(g => g.representative.severity === Severity.HIGH).length,
          medium: grouped.filter(g => g.representative.severity === Severity.MEDIUM).length,
          low: grouped.filter(g => g.representative.severity === Severity.LOW).length,
          info: grouped.filter(g => g.representative.severity === Severity.INFO).length
        }
      });
    } else {
      res.json(results);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('URL scan error:', message);
    res.status(500).json({ error: message });
  }
});

// Organize Vulnerabilities
app.post('/api/organize', async (req: Request, res: Response) => {
  try {
    const { scanResults, deduplicate = false } = req.body;
    
    if (!Array.isArray(scanResults)) {
      return res.status(400).json({ error: 'scanResults must be an array' });
    }

    // Convert timestamp strings back to Date objects
    const normalizedResults: ScanResult[] = scanResults.map((result: any) => ({
      ...result,
      timestamp: new Date(result.timestamp)
    }));

    if (deduplicate) {
      // Return deduplicated and organized results
      const result = organizer.organizeAndDeduplicate(normalizedResults);
      res.json(result);
    } else {
      // Return original organization
      const grouped = organizer.organize(normalizedResults);
      res.json(grouped);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Organize error:', message);
    res.status(500).json({ error: message });
  }
});

// Deduplicate Vulnerabilities (standalone endpoint)
app.post('/api/deduplicate', async (req: Request, res: Response) => {
  try {
    const { scanResults } = req.body;
    
    if (!Array.isArray(scanResults)) {
      return res.status(400).json({ error: 'scanResults must be an array' });
    }

    // Convert timestamp strings back to Date objects
    const normalizedResults: ScanResult[] = scanResults.map((result: any) => ({
      ...result,
      timestamp: new Date(result.timestamp)
    }));

    // Flatten all vulnerabilities
    const allVulnerabilities: Vulnerability[] = [];
    for (const result of normalizedResults) {
      allVulnerabilities.push(...result.vulnerabilities);
    }

    // Deduplicate
    const grouped = organizer.deduplicate(allVulnerabilities);
    res.json({ grouped, total: allVulnerabilities.length, unique: grouped.length });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Deduplicate error:', message);
    res.status(500).json({ error: message });
  }
});

// Simulate Exploit
app.post('/api/simulate', async (req: Request, res: Response) => {
  try {
    const { vulnerability, programSourcePath, userWalletAddress } = req.body;
    
    if (!vulnerability) {
      return res.status(400).json({ error: 'vulnerability is required' });
    }

    // Pass user wallet address if provided
    const exploitAttempt = await simulator.simulateExploit(
      vulnerability as Vulnerability,
      programSourcePath,
      userWalletAddress
    );
    res.json(exploitAttempt);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Simulation error:', message);
    res.status(500).json({ error: message });
  }
});

// Cleanup preserved repositories
app.post('/api/cleanup-repos', async (req: Request, res: Response) => {
  try {
    await gitScanner.cleanupPreservedRepos();
    res.json({
      success: true,
      message: 'Preserved repositories cleaned up successfully',
      warning: 'Repository preservation was disabled for security'
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Repository cleanup error:', message);
    res.status(500).json({ error: message });
  }
});

// Generate Bug Bounty Report
app.post('/api/report', async (req: Request, res: Response) => {
  try {
    const { vulnerability, exploitAttempt, author = 'Security Researcher' } = req.body;
    
    if (!vulnerability || !exploitAttempt) {
      return res.status(400).json({ 
        error: 'vulnerability and exploitAttempt are required' 
      });
    }

    const report = reporter.generateReport(
      vulnerability as Vulnerability,
      exploitAttempt as ExploitAttempt,
      author
    );
    const markdown = reporter.generateMarkdownReport(report);
    
    res.json({ report, markdown });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Report generation error:', message);
    res.status(500).json({ error: message });
  }
});

// Get scan result summary (for quick stats)
app.post('/api/summary', async (req: Request, res: Response) => {
  try {
    const { scanResults } = req.body;
    
    if (!Array.isArray(scanResults)) {
      return res.status(400).json({ error: 'scanResults must be an array' });
    }

    const normalizedResults: ScanResult[] = scanResults.map((result: any) => ({
      ...result,
      timestamp: new Date(result.timestamp)
    }));

    const grouped = organizer.organize(normalizedResults);
    res.json(grouped.summary);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Summary error:', message);
    res.status(500).json({ error: message });
  }
});

const PORT = parseInt(process.env.PORT || '3001', 10);

console.log(`🌐 Attempting to start server on port ${PORT}...`);

// Start server with explicit error handling
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ ==========================================`);
  console.log(`🚀 Xentinet Scanner API running on http://localhost:${PORT}`);
  console.log(`📚 API Documentation: See API_INTEGRATION_GUIDE.md`);
  console.log(`\n📡 Available endpoints:`);
  console.log(`  GET  /api/health`);
  console.log(`  POST /api/scan/contract/solana`);
  console.log(`  POST /api/scan/contract/evm`);
  console.log(`  POST /api/scan/git`);
  console.log(`  POST /api/scan/url`);
  console.log(`  POST /api/organize`);
  console.log(`  POST /api/simulate`);
  console.log(`  POST /api/report`);
  console.log(`  POST /api/summary`);
  console.log(`✅ ==========================================\n`);
}).on('error', (err: NodeJS.ErrnoException) => {
  console.error(`\n❌ ==========================================`);
  console.error(`❌ Server failed to start!`);
  console.error(`❌ Error: ${err.message}`);
  
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use.`);
    console.error(`❌ Try: netstat -ano | findstr :${PORT}`);
    console.error(`❌ Or change PORT in .env file`);
  } else if (err.code === 'EACCES') {
    console.error(`❌ Permission denied. Port ${PORT} requires elevated privileges.`);
  }
  
  console.error(`❌ ==========================================\n`);
  process.exit(1);
});

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  server.close(() => {
    process.exit(1);
  });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  server.close(() => {
    process.exit(1);
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\n🛑 SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

