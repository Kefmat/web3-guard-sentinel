import * as fs from 'fs';
import * as path from 'path';
import { ScanReport } from '../types/security.js';
import { HtmlReporter } from './htmlReporter.js';

/**
 * Handles compiling structured data metrics and routing report files to disk.
 * @author Kevin Matarewicz
 */
export class FileReporter {
    /**
     * Dispatches tasks to generate Markdown, JSON, and interactive HTML security reports.
     * @param report The collected scan dataset to write out.
     */
    public static generateAutomatedReports(report: ScanReport): void {
        const outputDir = path.join(process.cwd(), 'reports');

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        // 1. Write the raw JSON dataset
        const jsonPath = path.join(outputDir, 'security-report.json');
        fs.writeFileSync(jsonPath, JSON.stringify(report, null, 4), 'utf8');
        console.log(`Report: Structured data exported to ${jsonPath}`);

        // 2. Write the developer markdown summary
        const mdPath = path.join(outputDir, 'security-report.md');
        const mdContent = this.buildMarkdownString(report);
        fs.writeFileSync(mdPath, mdContent, 'utf8');
        console.log(`Report: Human-readable log exported to ${mdPath}`);

        // 3. Write the interactive visual HTML panel
        HtmlReporter.generateDashboard(report, outputDir);
    }

    /**
     * Constructs a clean, professional markdown summary document without tracking decorative emoji symbols.
     * @param report The collected scan dataset.
     * @returns A formatted string structure containing the audit report.
     */
    private static buildMarkdownString(report: ScanReport): string {
        let md = `# Security Audit Compliance Report\n\n`;
        md += `* **Scan Date**: ${new Date(report.timestamp).toUTCString()}\n`;
        md += `* **Target Scope**: ${report.targetFile}\n`;
        md += `* **Modules Analyzed**: ${report.summary.totalDependenciesScanned}\n`;
        md += `* **Total Vulnerabilities**: ${report.summary.vulnerabilitiesIdentified}\n\n`;

        md += `## Vulnerability Inventory\n\n`;
        if (report.findings.length === 0) {
            md += `[PASSED] Zero compliance violations or vulnerabilities uncovered across the audited project scope.\n`;
        } else {
            md += `| Severity | Target Component | Finding Details |\n`;
            md += `| :--- | :--- | :--- |\n`;
            for (const finding of report.findings) {
                md += `| **${finding.severity}** | \`${finding.library}\` | ${finding.description} |\n`;
            }
        }
        return md;
    }
}