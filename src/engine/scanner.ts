import * as fs from 'fs';
import * as path from 'path';
import { VULNERABILITY_REGISTRY } from '../registry/vulnerabilities.js';
import { VulnerabilityFinding, ScanReport } from '../types/security.js';
import { FileReporter } from '../reporters/fileReporter.js';
import { OsvService } from '../services/osvService.js';

/**
 * Handles file reading, dependency evaluation, and build enforcement tasks.
 */
export class ScannerEngine {
    // Severity weight mappings to programmatically calculate threshold breaches
    private static readonly SEVERITY_WEIGHTS: Record<string, number> = {
        'LOW': 1,
        'MEDIUM': 2,
        'HIGH': 3,
        'CRITICAL': 4
    };

    /**
     * Audits the dependencies found within the target project directory.
     * @param targetDirectory The project directory containing the package.json.
     * @param failThreshold The minimum severity level required to fail the build.
     */
    public static async auditDependencies(targetDirectory: string, failThreshold: string | null): Promise<void> {
        const filePath = path.join(targetDirectory, 'package.json');

        if (!fs.existsSync(filePath)) {
            console.error(`Error: Target manifest file not found at ${filePath}`);
            process.exit(1);
        }

        try {
            console.log(`System: Scanning manifest file at ${filePath}...`);
            const fileContent = fs.readFileSync(filePath, 'utf8');
            const manifest = JSON.parse(fileContent);
            
            const dependencies = {
                ...manifest.dependencies,
                ...manifest.devDependencies
            };

            console.log("Status: Analyzing dependency tree...");
            await this.evaluateVulnerabilities(dependencies, filePath, failThreshold);

        } catch (error) {
            console.error("Error: Failed to parse the target manifest file safely.");
            process.exit(1);
        }
    }

    /**
     * Evaluates identified dependencies and checks if severity limits are breached.
     */
    private static async evaluateVulnerabilities(dependencies: Record<string, string>, targetFile: string, failThreshold: string | null): Promise<void> {
        let findings: VulnerabilityFinding[] = [];
        let totalScanned = 0;
        const apiQueries: Promise<VulnerabilityFinding[]>[] = [];

        for (const [pkg, version] of Object.entries(dependencies)) {
            totalScanned++;
            const localRule = VULNERABILITY_REGISTRY[pkg];
            if (localRule) {
                console.warn(`[LOCAL MATCH] Static rule fallback hit for library: ${pkg}`);
                findings.push({
                    library: pkg,
                    installedVersion: version,
                    severity: localRule.severity,
                    description: localRule.description
                });
            }
            apiQueries.push(OsvService.queryPackage(pkg, version));
        }

        console.log("Status: Dispatching concurrent query pool to live OSV threat feed...");
        const apiResults = await Promise.all(apiQueries);
        
        apiResults.forEach((result) => {
            if (result.length > 0) {
                result.forEach((finding) => {
                    console.warn(`[LIVE ADVISORY] Upstream threat tracked for package: ${finding.library} (${finding.cveId})`);
                });
                findings = [...findings, ...result];
            }
        });

        console.log(`\nScan complete. Total vulnerabilities identified: ${findings.length}`);

        const report: ScanReport = {
            timestamp: new Date().toISOString(),
            targetFile: path.basename(targetFile),
            summary: {
                totalDependenciesScanned: totalScanned,
                vulnerabilitiesIdentified: findings.length
            },
            findings: findings
        };

        FileReporter.generateAutomatedReports(report);

        // Check if any finding breaches the automated pipeline threshold flag
        if (failThreshold && this.SEVERITY_WEIGHTS[failThreshold.toUpperCase()]) {
            const targetWeight = this.SEVERITY_WEIGHTS[failThreshold.toUpperCase()]!;
            let breachDetected = false;

            for (const finding of findings) {
                const findingWeight = this.SEVERITY_WEIGHTS[finding.severity] || 0;
                if (findingWeight >= targetWeight) {
                    console.error(`\n[PIPELINE FAILURE] Severity threshold breach: Found ${finding.severity} issue in ${finding.library}.`);
                    breachDetected = true;
                }
            }

            if (breachDetected) {
                console.error("System Action: Terminating execution process with failure code.");
                process.exit(1);
            }
        }
    }
}