import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityFinding } from '../types/security.js';

/**
 * Static Analysis Engine for Solidity Smart Contracts.
 * Parses source code line-by-line to identify critical Web3 security patterns.
 * * @author Kevin Matarewicz
 */
export class ContractScannerEngine {
    /**
     * Scans all Solidity files inside a target directory for high-risk vulnerability patterns.
     * * @param targetDirectory The project directory to scan.
     * @returns An array of identified vulnerability findings.
     */
    public static scanContracts(targetDirectory: string): VulnerabilityFinding[] {
        const findings: VulnerabilityFinding[] = [];
        
        if (!fs.existsSync(targetDirectory)) {
            return findings;
        }

        const files = fs.readdirSync(targetDirectory);
        const solidityFiles = files.filter(file => file.endsWith('.sol'));

        if (solidityFiles.length === 0) {
            return findings;
        }

        console.log(`System: Found ${solidityFiles.length} Solidity smart contracts. Initializing AST-Heuristic scanner...`);

        solidityFiles.forEach((file) => {
            const fullPath = path.join(targetDirectory, file);
            const content = fs.readFileSync(fullPath, 'utf8');
            const lines = content.split('\n');

            let matchesReentrancyPattern = false;
            let checksBalancesAfterCall = false;

            lines.forEach((line, index) => {
                const lineNumber = index + 1;

                // 1. Check for dangerous usage of tx.origin for authorization
                if (line.includes('tx.origin') && (line.includes('msg.sender') || line.includes('require'))) {
                    findings.push({
                        library: `${file} (Line ${lineNumber})`,
                        installedVersion: 'Solidity Native',
                        severity: 'HIGH',
                        description: `Insecure Authorization: Using 'tx.origin' for access control makes the contract highly vulnerable to phishing/phreaking attacks via malicious proxy call intersections. Use 'msg.sender' instead.`
                    });
                }

                // 2. Check for unsafe outdated compiler pragma definitions
                if (line.includes('pragma solidity') && (line.includes('0.4.') || line.includes('0.5.') || line.includes('0.6.'))) {
                    findings.push({
                        library: `${file} (Line ${lineNumber})`,
                        installedVersion: 'Solidity Native',
                        severity: 'MEDIUM',
                        description: `Outdated Compiler Version: Using a deprecated compiler version leaves the contract exposed to known, unpatched compiler-level bugs. Upgrade to a stable version (e.g., ^0.8.20).`
                    });
                }

                // 3. Track low-level call patterns to flag potential Reentrancy vulnerabilities
                if (line.includes('.call{value:')) {
                    matchesReentrancyPattern = true;
                }
                // Check if balance state logic occurs AFTER the call (Checks-Effects-Interactions violation)
                if (matchesReentrancyPattern && (line.includes('balances[') || line.includes('_balances[')) && line.includes('=')) {
                    checksBalancesAfterCall = true;
                }
            });

            if (matchesReentrancyPattern && checksBalancesAfterCall) {
                findings.push({
                    library: file,
                    installedVersion: 'Solidity Native',
                    severity: 'CRITICAL',
                    description: `Potential Reentrancy Vulnerability: Contract performs an external state transfer invocation via a low-level '.call' before updating internal state balances. This violates the Checks-Effects-Interactions pattern and exposes funds to drain exploits.`
                });
            }
        });

        return findings;
    }
}