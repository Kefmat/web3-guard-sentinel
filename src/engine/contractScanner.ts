import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityFinding } from '../types/security.js';

/**
 * Static Application Security Testing (SAST) engine for Solidity source code files.
 * Employs multi-point pattern matching to detect anti-patterns and vulnerabilities.
 * * @author Kevin Matarewicz
 */
export class ContractScannerEngine {
    /**
     * Recursively scans the targeted directory paths for all Solidity (*.sol) source assets.
     * * @param targetDirectory The base project workspace path to analyze.
     * @returns An array containing collected vulnerability findings.
     */
    public static scanContracts(targetDirectory: string): VulnerabilityFinding[] {
        const findings: VulnerabilityFinding[] = [];

        if (!fs.existsSync(targetDirectory)) {
            return findings;
        }

        const executeSearch = (currentPath: string) => {
            const files = fs.readdirSync(currentPath);

            for (const file of files) {
                const fullPath = path.join(currentPath, file);
                const stat = fs.statSync(fullPath);

                if (stat.isDirectory()) {
                    // Avoid searching standard build and package manager artifact caches
                    if (file !== 'node_modules' && file !== 'artifacts' && file !== 'cache' && file !== 'dist') {
                        executeSearch(fullPath);
                    }
                } else if (file.endsWith('.sol')) {
                    console.log(`System: Running static heuristics on contract asset: ${fullPath}`);
                    const contractFindings = this.analyzeContractContent(fullPath);
                    findings.push(...contractFindings);
                }
            }
        };

        executeSearch(targetDirectory);
        return findings;
    }

    /**
     * Inspects the textual lines of a single Solidity file to intercept technical design threats.
     * * @param filePath The local path to the target contract asset.
     * @returns An array containing discovered structural vulnerabilities.
     */
    private static analyzeContractContent(filePath: string): VulnerabilityFinding[] {
        const findings: VulnerabilityFinding[] = [];
        const fileName = path.basename(filePath);
        
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.split(/\r?\n/);

            let insideInlineAssemblyBlock = false;

            for (let i = 0; i < lines.length; i++) {
                const rawLine = lines[i];
                if (rawLine === undefined) continue;

                const line = rawLine.trim();
                const lineNumber = i + 1;

                // Skip processing empty spaces or standalone comments to prevent false matching flags
                if (line.length === 0 || line.startsWith('//') || line.startsWith('*') || line.startsWith('/*')) {
                    continue;
                }

                // Vector 1: Reentrancy (State mutation following low-level communication streams)
                if (line.includes('.call{') && line.includes('value:')) {
                    // Inspect immediate lookahead lines for unsafe subsequent state modification assignments
                    for (let j = 1; j <= 4; j++) {
                        const lookaheadLine = lines[i + j];
                        if (!lookaheadLine) break;
                        
                        const trimmedLookahead = lookaheadLine.trim();
                        if (trimmedLookahead.includes('balance') || trimmedLookahead.includes('=_') || (trimmedLookahead.includes('[') && trimmedLookahead.includes('='))) {
                            findings.push({
                                library: `${fileName} (Line ${lineNumber})`,
                                installedVersion: 'Solidity Codebase',
                                severity: 'CRITICAL',
                                description: 'Potential Reentrancy exposure: Low-level call validation pattern flags consecutive state changes outside safe transactional sequencing rules.'
                            });
                            break;
                        }
                    }
                }

                // Vector 2: Insecure Transaction Authorization Origin Checks
                if (line.includes('tx.origin')) {
                    findings.push({
                        library: `${fileName} (Line ${lineNumber})`,
                        installedVersion: 'Solidity Codebase',
                        severity: 'HIGH',
                        description: 'Insecure authorization pattern: Relying on tx.origin for access controls exposes functions to phishing proxy contract intervention attacks.'
                    });
                }

                // Vector 3: Outdated or Vulnerable Compiler Configurations
                if (line.startsWith('pragma solidity')) {
                    const outdatedPattern = /0\.(4|5|6|7)\./;
                    if (outdatedPattern.test(line)) {
                        findings.push({
                            library: `${fileName} (Line ${lineNumber})`,
                            installedVersion: 'Solidity Codebase',
                            severity: 'MEDIUM',
                            description: 'Outdated compiler configuration: Lock specifications under version 0.8.0 expose bytecode assets to historic compilation bugs and unexpected state overflows.'
                        });
                    }
                }

                // Vector 4: Unprotected Proxy Initializer Functions
                if (line.includes('function initialize') && !line.includes('initializer') && !line.includes('onlyOwner')) {
                    findings.push({
                        library: `${fileName} (Line ${lineNumber})`,
                        installedVersion: 'Solidity Codebase',
                        severity: 'HIGH',
                        description: 'Unprotected contract proxy initializer detected: Missing structural initializer protection rules allows front-running configuration privileges.'
                    });
                }

                // Vector 5: Dangerous State Self-Destruction Instructions
                if (line.includes('selfdestruct(') || line.includes('suicide(')) {
                    findings.push({
                        library: `${fileName} (Line ${lineNumber})`,
                        installedVersion: 'Solidity Codebase',
                        severity: 'CRITICAL',
                        description: 'Dangerous state destruction function: Use of selfdestruct leaves contracts vulnerable to balance trapping and arbitrary logic loss.'
                    });
                }

                // Vector 6: Inline Yul Assembly Engine Detection
                if (line.includes('assembly {')) {
                    insideInlineAssemblyBlock = true;
                }
                if (insideInlineAssemblyBlock && line.includes('}')) {
                    findings.push({
                        library: `${fileName} (Line ${lineNumber})`,
                        installedVersion: 'Solidity Codebase',
                        severity: 'LOW',
                        description: 'Informational: Inline assembly block (Yul dialect) observed. Custom low-level logic operations bypass standard memory boundaries and require strict code verification.'
                    });
                    insideInlineAssemblyBlock = false;
                }
            }

        } catch (error) {
            console.error(`Error: Failed to process static analysis for source file asset path: ${filePath}`);
        }

        return findings;
    }
}