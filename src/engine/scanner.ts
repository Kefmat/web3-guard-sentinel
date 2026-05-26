import * as fs from 'fs';
import * as path from 'path';
import { VULNERABILITY_REGISTRY } from '../registry/vulnerabilities.js';
import { VulnerabilityFinding, ScanReport } from '../types/security.js';
import { FileReporter } from '../reporters/fileReporter.js';
import { OsvService } from '../services/osvService.js';
import { ContractScannerEngine } from './contractScanner.js';
import { SemVerUtil } from '../utils/semver.js';

/**
 * Handles file reading, dependency evaluation, lockfile graph traversal, and build enforcement tasks.
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
        const packageJsonPath = path.join(targetDirectory, 'package.json');
        const lockfileJsonPath = path.join(targetDirectory, 'package-lock.json');
        
        let dependencyFindings: VulnerabilityFinding[] = [];
        let totalScanned = 0;
        let scanTargetContext = 'Contracts Only';

        // Check for deep lockfile availability first, then fall back to traditional manifest files
        if (fs.existsSync(lockfileJsonPath)) {
            try {
                console.log(`System: Found deep lockfile at ${lockfileJsonPath}. Parsing full graph layout...`);
                const fileContent = fs.readFileSync(lockfileJsonPath, 'utf8');
                const lockfile = JSON.parse(fileContent);
                
                const dependenciesToScan: Record<string, string> = {};

                // Parse modern lockfile formats (v2 & v3 contain a flat 'packages' tree map)
                if (lockfile.packages) {
                    for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
                        if (pkgPath === '' || !pkgInfo || typeof pkgInfo !== 'object' || !('version' in pkgInfo)) {
                            continue;
                        }
                        // Clean out the "node_modules/" prefix path string
                        const cleanPkgName = pkgPath.replace(/^node_modules\//, '');
                        if (cleanPkgName && typeof pkgInfo.version === 'string') {
                            dependenciesToScan[cleanPkgName] = pkgInfo.version;
                        }
                    }
                } else if (lockfile.dependencies) {
                    // Backwards fallback support for legacy v1 lockfile formats
                    for (const [pkgName, pkgInfo] of Object.entries(lockfile.dependencies)) {
                        if (pkgInfo && typeof pkgInfo === 'object' && 'version' in pkgInfo && typeof pkgInfo.version === 'string') {
                            dependenciesToScan[pkgName] = pkgInfo.version;
                        }
                    }
                }

                console.log(`Status: Analyzing complete graph consisting of ${Object.keys(dependenciesToScan).length} transitive dependencies...`);
                const result = await this.evaluateDependencies(dependenciesToScan);
                dependencyFindings = result.findings;
                totalScanned = result.totalScanned;
                scanTargetContext = 'package-lock.json & Contracts';

            } catch (error) {
                console.error("Warning: Lockfile evaluation process aborted due to corruption errors.");
            }
        } else if (fs.existsSync(packageJsonPath)) {
            try {
                console.log(`System: Lockfile absent. Parsing top-level manifest file at ${packageJsonPath}...`);
                const fileContent = fs.readFileSync(packageJsonPath, 'utf8');
                const manifest = JSON.parse(fileContent);
                
                const dependencies = {
                    ...manifest.dependencies,
                    ...manifest.devDependencies
                };

                console.log("Status: Analyzing dependency tree...");
                const result = await this.evaluateDependencies(dependencies);
                dependencyFindings = result.findings;
                totalScanned = result.totalScanned;
                scanTargetContext = 'package.json & Contracts';

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
            targetFile: scanTargetContext,
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