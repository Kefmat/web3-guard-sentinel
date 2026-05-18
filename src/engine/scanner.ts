import * as fs from 'fs';
import * as path from 'path';
import { VULNERABILITY_REGISTRY } from '../registry/vulnerabilities.js';
import { VulnerabilityFinding, ScanReport } from '../types/security.js';
import { FileReporter } from '../reporters/fileReporter.js';

/**
 * Handles file reading and dependency evaluation tasks.
 */
export class ScannerEngine {
    /**
     * Audits the dependencies found within the target package.json file.
     * @param filePath The absolute path to the file to be analyzed.
     */
    public static auditDependencies(filePath: string): void {
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
            this.evaluateVulnerabilities(dependencies, filePath);

        } catch (error) {
            console.error("Error: Failed to parse the target manifest file safely.");
        }
    }

    /**
     * Evaluates identified dependencies against the internal registry.
     */
    private static evaluateVulnerabilities(dependencies: Record<string, string>, targetFile: string): void {
        const findings: VulnerabilityFinding[] = [];
        let totalScanned = 0;

        for (const [pkg, version] of Object.entries(dependencies)) {
            totalScanned++;
            const rule = VULNERABILITY_REGISTRY[pkg];
            if (rule) {
                console.warn(`\n[WARNING] Vulnerability detected in library: ${pkg}`);
                console.warn(`Installed Version: ${version}`);
                console.warn(`Severity: ${rule.severity}`);
                console.warn(`Description: ${rule.description}`);

                findings.push({
                    library: pkg,
                    installedVersion: version,
                    severity: rule.severity,
                    description: rule.description
                });
            }
        }

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