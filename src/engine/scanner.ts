import * as fs from 'fs';
import * as path from 'path';
import { VULNERABILITY_REGISTRY } from '../registry/vulnerabilities.js';
import { VulnerabilityFinding, ScanReport } from '../types/security.js';
import { FileReporter } from '../reporters/fileReporter.js';
import { OsvService } from '../services/osvService.js';

/**
 * Handles file reading and dependency evaluation tasks.
 */
export class ScannerEngine {
    /**
     * Audits the dependencies found within the target package.json file.
     * @param filePath The absolute path to the file to be analyzed.
     */
    public static async auditDependencies(filePath: string): Promise<void> {
        if (!fs.existsSync(filePath)) {
            console.error(`Error: Target manifest file not found at ${filePath}`);
            return;
        }

        try {
            console.log("System: Scanning for project manifest files...");
            const fileContent = fs.readFileSync(filePath, 'utf8');
            const manifest = JSON.parse(fileContent);
            
            const dependencies = {
                ...manifest.dependencies,
                ...manifest.devDependencies
            };

            console.log("Status: Analyzing dependency tree...");
            await this.evaluateVulnerabilities(dependencies, filePath);

        } catch (error) {
            console.error("Error: Failed to parse the target manifest file safely.");
        }
    }

    /**
     * Evaluates identified dependencies against both local rules and live API feeds.
     */
    private static async evaluateVulnerabilities(dependencies: Record<string, string>, targetFile: string): Promise<void> {
        let findings: VulnerabilityFinding[] = [];
        let totalScanned = 0;

        // Prepare an array of asynchronous tasks for the live API query pool
        const apiQueries: Promise<VulnerabilityFinding[]>[] = [];

        for (const [pkg, version] of Object.entries(dependencies)) {
            totalScanned++;

            // 1. Fallback evaluation via local registry rule definitions
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

            // 2. Queue live upstream threat evaluation task via OSV API
            apiQueries.push(OsvService.queryPackage(pkg, version));
        }

        console.log("Status: Dispatching concurrent query pool to live OSV threat feed...");
        const apiResults = await Promise.all(apiQueries);
        
        // Flatten the array of arrays from the API query pools into the main findings ledger
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
    }
}