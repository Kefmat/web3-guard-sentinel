import * as fs from 'fs';
import * as path from 'path';
import { ScanReport } from '../types/security.js';

/**
 * Handles automation of security compliance reporting outputs.
 */
export class FileReporter {
    /**
     * Generates both JSON and Markdown format audit reports for DevSecOps pipelines.
     * @param report The final constructed scan report structure.
     */
    public static generateAutomatedReports(report: ScanReport): void {
        const outputDir = path.join(process.cwd(), 'reports');
        
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const jsonPath = path.join(outputDir, 'security-report.json');
        fs.writeFileSync(jsonPath, JSON.stringify(report, null, 4), 'utf8');
        console.log(`Report: Structured data exported to ${jsonPath}`);

        const mdPath = path.join(outputDir, 'security-report.md');
        let mdContent = `# Web3-Guard Sentinel Security Report\n\n`;
        mdContent += `**Timestamp:** ${report.timestamp}  \n`;
        mdContent += `**Target File Location:** \`${report.targetFile}\`  \n\n`;
        mdContent += `## Executive Summary\n\n`;
        mdContent += `| Metric | Value |\n| --- | --- |\n`;
        mdContent += `| Total Dependencies Audited | ${report.summary.totalDependenciesScanned} |\n`;
        mdContent += `| Vulnerabilities Flagged | ${report.summary.vulnerabilitiesIdentified} |\n\n`;
        mdContent += `## Detailed Findings\n\n`;

        if (report.findings.length === 0) {
            mdContent += `No known security vulnerabilities were identified within this project configuration.\n`;
        } else {
            report.findings.forEach((finding) => {
                mdContent += `### [${finding.severity}] Security Issue in \`${finding.library}\`\n`;
                mdContent += `- **Installed Package Version:** ${finding.installedVersion}\n`;
                mdContent += `- **Threat Context:** ${finding.description}\n\n`;
            });
        }

        fs.writeFileSync(mdPath, mdContent, 'utf8');
        console.log(`Report: Human-readable log exported to ${mdPath}`);
    }
}