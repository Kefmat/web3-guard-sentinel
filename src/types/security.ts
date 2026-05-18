/**
 * Represents an individual vulnerability rule in the registry.
 */
export interface VulnerabilityRule {
    versionRange: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
}

/**
 * Represents a specific vulnerability found during a project scan.
 */
export interface VulnerabilityFinding {
    library: string;
    installedVersion: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
}

/**
 * Represents the final aggregated scan report object.
 */
export interface ScanReport {
    timestamp: string;
    targetFile: string;
    summary: {
        totalDependenciesScanned: number;
        vulnerabilitiesIdentified: number;
    };
    findings: VulnerabilityFinding[];
}