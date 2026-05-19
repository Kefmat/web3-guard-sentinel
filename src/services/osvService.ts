import { VulnerabilityFinding } from '../types/security.js';

/**
 * Service to interact with the Google Open Source Vulnerability (OSV) API.
 * Provides live vulnerability intelligence data for open-source ecosystems.
 * * @author Kevin Matarewicz
 */
export class OsvService {
    private static readonly OSV_API_URL = 'https://api.osv.dev/v1/query';

    /**
     * Queries the live OSV database for threats targeting a specific package package and version.
     * * @param packageName The name of the NPM package to audit.
     * @param version The currently installed version of the package.
     * @returns A promise resolving to an array of identified vulnerability findings.
     */
    public static async queryPackage(packageName: string, version: string): Promise<VulnerabilityFinding[]> {
        const findings: VulnerabilityFinding[] = [];
        
        // Clean version string to eliminate common SemVer prefixes (^, ~, etc.)
        const cleanVersion = version.replace(/[^0-9.]/g, '');

        const requestBody = {
            version: cleanVersion,
            package: {
                name: packageName,
                ecosystem: 'npm'
            }
        };

        try {
            const response = await fetch(this.OSV_API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                // Return empty findings if the upstream API fails to prevent blocking execution
                return findings;
            }

            const data = await response.json() as { vulns?: Array<{ id: string; summary?: string; details?: string }> };
            
            // If the vulnerabilities property exists, the package has known threats
            if (data.vulns && data.vulns.length > 0) {
                data.vulns.forEach((vuln) => {
                    findings.push({
                        library: packageName,
                        installedVersion: version,
                        severity: 'HIGH', // Fallback default mapping for API threats
                        description: vuln.summary || vuln.details || 'No detailed vulnerability breakdown provided.',
                        cveId: vuln.id
                    });
                });
            }
        } catch (error) {
            console.error(`System Error: Failed network handshake with OSV API for package ${packageName}`);
        }

        return findings;
    }
}