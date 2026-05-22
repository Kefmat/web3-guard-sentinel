import * as fs from 'fs';
import * as path from 'path';
import { VULNERABILITY_REGISTRY } from '../registry/vulnerabilities.js';
import { VulnerabilityFinding, ScanReport } from '../types/security.js';
import { FileReporter } from '../reporters/fileReporter.js';
import { OsvService } from '../services/osvService.js';
import { ContractScannerEngine } from './contractScanner.js';
import { SemVerUtil } from '../utils/semver.js';

/**
 * Handles file reading, dependency evaluation, and build enforcement tasks.
 * * @author Kevin Matarewicz
 */
export class ScannerEngine {
    private static readonly SEVERITY_WEIGHTS: Record<string, number> = {
        'LOW': 1,
        'MEDIUM': 2,
        'HIGH': 3,
        'CRITICAL': 4
    };

    /**
     * Audits the dependencies and smart contracts found within the target project directory.
     * * @param targetDirectory The project directory containing assets.
     * @param failThreshold The minimum severity level required to fail the build.
     */
    public static async auditDependencies(targetDirectory: string, failThreshold: string | null): Promise<void> {
        const filePath = path.join(targetDirectory, 'package.json');
        let dependencyFindings: VulnerabilityFinding[] = [];
        let totalScanned = 0;

        if (fs.existsSync(filePath)) {
            try {
                console.log(`System: Scanning manifest file at ${filePath}...`);
                const fileContent = fs.readFileSync(filePath, 'utf8');
                const manifest = JSON.parse(fileContent);
                
                const dependencies = {
                    ...manifest.dependencies,
                    ...manifest.devDependencies
                };

                console.log("Status: Analyzing dependency tree...");
                const result = await this.evaluateDependencies(dependencies);
                dependencyFindings = result.findings;
                totalScanned = result.totalScanned;

            } catch (error) {
                console.error("Error: Failed to parse the target manifest file safely.");
                process.exit(1);
            }
        }

        const contractFindings = ContractScannerEngine.scanContracts(targetDirectory);
        const allFindings = [...dependencyFindings, ...contractFindings];

        console.log(`\nScan complete. Total vulnerabilities identified: ${allFindings.length}`);

        const report: ScanReport = {
            timestamp: new Date().toISOString(),
            targetFile: fs.existsSync(filePath) ? 'package.json & Contracts' : 'Contracts Only',
            summary: {
                totalDependenciesScanned: totalScanned,
                vulnerabilitiesIdentified: allFindings.length
            },
            findings: allFindings
        };

        FileReporter.generateAutomatedReports(report);

        if (failThreshold && this.SEVERITY_WEIGHTS[failThreshold.toUpperCase()]) {
            const targetWeight = this.SEVERITY_WEIGHTS[failThreshold.toUpperCase()]!;
            let breachDetected = false;

            for (const finding of allFindings) {
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

    /**
     * Helper to process dependencies against local definitions and the OSV API.
     * Includes an explicit type guard to safely handle potentially undefined string values.
     * * @param dependencies Record layout of package target variations.
     * @returns An object containing grouped vulnerability findings and total scanned count.
     */
    private static async evaluateDependencies(dependencies: Record<string, string | undefined>): Promise<{ findings: VulnerabilityFinding[], totalScanned: number }> {
        const findings: VulnerabilityFinding[] = [];
        let totalScanned = 0;
        const apiQueries: Promise<VulnerabilityFinding[]>[] = [];

        for (const [pkg, versionRange] of Object.entries(dependencies)) {
            totalScanned++;
            
            // Cast or fall back to an empty string if the version range is undefined to meet type constraints
            const safeVersionRange = typeof versionRange === 'string' ? versionRange : '';
            
            // Normalize the SemVer range string into a clean, exact version format
            const cleanVersion = SemVerUtil.normalizeVersion(safeVersionRange);

            const localRule = VULNERABILITY_REGISTRY[pkg];
            if (localRule) {
                findings.push({
                    library: pkg,
                    installedVersion: cleanVersion,
                    severity: localRule.severity,
                    description: localRule.description
                });
            }
            
            // Dispatch the normalized version to the live OSV threat feed
            apiQueries.push(OsvService.queryPackage(pkg, cleanVersion));
        }

        console.log("Status: Dispatching concurrent query pool to live OSV threat feed...");
        const apiResults = await Promise.all(apiQueries);
        
        apiResults.forEach((result) => {
            if (result.length > 0) {
                findings.push(...result);
            }
        });

        return { findings, totalScanned };
    }
}