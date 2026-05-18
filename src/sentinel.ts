import * as fs from 'fs';
import * as path from 'path';

/**
 * Web3-Guard Sentinel
 * * Core scanning engine that analyzes project manifest files to identify
 * known vulnerabilities in Web3 dependencies and cryptographic libraries.
 */
class Sentinel {
    // A local registry simulating known vulnerable Web3 library versions
    private static readonly VULNERABILITY_REGISTRY: Record<string, { versionRange: string; severity: string; description: string }> = {
        'ethers': {
            versionRange: '<5.7.0',
            severity: 'HIGH',
            description: 'Potential padding oracle vulnerability in cryptographic decryption routines.'
        },
        'web3': {
            versionRange: '<1.8.0',
            severity: 'CRITICAL',
            description: 'Insecure handling of private keys during local wallet creation.'
        }
    };

    /**
     * Main execution context for the security scanner.
     */
    public static main(): void {
        console.log("Web3-Guard Sentinel v1.0.0");
        console.log("Status: Initializing security modules...");
        
        const targetPath = path.join(process.cwd(), 'package.json');
        this.auditDependencies(targetPath);
    }

    /**
     * Audits the dependencies found within the target package.json file.
     * * @param filePath The absolute path to the package.json file to be analyzed.
     */
    private static auditDependencies(filePath: string): void {
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
            this.evaluateVulnerabilities(dependencies);

        } catch (error) {
            console.error("Error: Failed to parse the target manifest file safely.");
        }
    }

    /**
     * Evaluates identified dependencies against the internal vulnerability registry.
     * * @param dependencies Object containing the package names and versions.
     */
    private static evaluateVulnerabilities(dependencies: Record<string, string>): void {
        let issuesFound = 0;

        for (const [pkg, version] of Object.entries(dependencies)) {
            if (this.VULNERABILITY_REGISTRY[pkg]) {
                const cleanVersion = version.replace(/[^0-9.]/g, '');
                const rule = this.VULNERABILITY_REGISTRY[pkg];
                
                console.warn(`\n[WARNING] Vulnerability detected in library: ${pkg}`);
                console.warn(`Installed Version: ${version}`);
                console.warn(`Severity: ${rule.severity}`);
                console.warn(`Description: ${rule.description}`);
                issuesFound++;
            }
        }

        console.log(`\nScan complete. Total vulnerabilities identified: ${issuesFound}`);
    }
}

Sentinel.main();