import * as fs from 'fs';
import * as path from 'path';
import { VULNERABILITY_REGISTRY } from '../registry/vulnerabilities.js';
import { VulnerabilityFinding, ScanReport } from '../types/security.js';
import { FileReporter } from '../reporters/fileReporter.js';
import { OsvService } from '../services/osvService.js';
import { ContractScannerEngine } from './contractScanner.js';

/**
 * Handles file reading, dependency evaluation, and build enforcement tasks.
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
     * @param targetDirectory The project directory containing assets.
     * @param failThreshold The minimum severity level required to fail the build.
     */
    public static async auditDependencies(targetDirectory: string, failThreshold: string | null): Promise<void> {
        const filePath = path.join(targetDirectory, 'package.json');
        let dependencyFindings: VulnerabilityFinding[] = [];
        let totalScanned = 0;

        // 1. Dependency Analysis Phase
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

        // 2. Smart Contract Analysis Phase
        const contractFindings = ContractScannerEngine.scanContracts(targetDirectory);
        
        // Combine all findings into a single unified ledger
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

        // Policy Enforcement Threshold Check
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
     */
    private static async evaluateDependencies(dependencies: Record<string, string>): Promise<{ findings: VulnerabilityFinding[], totalScanned: number }> {
        const findings: VulnerabilityFinding[] = [];
        let totalScanned = 0;
        const apiQueries: Promise<VulnerabilityFinding[]>[] = [];

        for (const [pkg, version] of Object.entries(dependencies)) {
            totalScanned++;
            const localRule = VULNERABILITY_REGISTRY[pkg];
            if (localRule) {
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
                findings.push(...result);
            }
        });

        return { findings, totalScanned };
    }
}