import { Vulnerability } from "../types/vulnerability.js";

/**
 * Base class for all vulnerability detectors
 */
export abstract class BaseDetector {
  abstract name: string;
  abstract description: string;

  /**
   * Scan content for vulnerabilities
   */
  abstract detect(content: string, context?: any): Promise<Vulnerability[]>;

  /**
   * Check if this detector is applicable to the given file type
   */
  abstract isApplicable(filePath: string): boolean;
}

