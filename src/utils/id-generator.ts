import * as crypto from "crypto";

/**
 * Generate a unique vulnerability ID
 * Includes file path, line number, and a hash to ensure uniqueness
 */
export function generateVulnerabilityId(
  type: string,
  filePath: string | undefined,
  lineNumber: number,
  index?: number
): string {
  // Normalize type (remove spaces, lowercase)
  const normalizedType = type
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-]/g, '');
  
  // Get file name or use 'unknown'
  const fileName = filePath 
    ? filePath.split(/[/\\]/).pop()?.replace(/[^a-z0-9.-]/gi, '_') || 'unknown'
    : 'unknown';
  
  // Create a hash from file path + line + type to ensure uniqueness
  const hashInput = `${filePath || ''}-${lineNumber}-${type}-${index || 0}`;
  const hash = crypto.createHash('md5').update(hashInput).digest('hex').slice(0, 8);
  
  // Generate ID: type-file-line-hash
  return `${normalizedType}-${fileName}-${lineNumber}-${hash}`;
}

/**
 * Generate a unique ID for grouped vulnerabilities
 */
export function generateGroupedId(
  groupKey: string,
  index: number
): string {
  const hash = crypto.createHash('md5').update(`${groupKey}-${index}`).digest('hex').slice(0, 8);
  return `group-${hash}-${index}`;
}

