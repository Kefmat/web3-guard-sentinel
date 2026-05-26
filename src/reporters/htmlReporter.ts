import * as fs from 'fs';
import * as path from 'path';
import { ScanReport } from '../types/security.js';
import { DASHBOARD_STYLES } from './theme.js';

/**
 * Generates an interactive, production-ready HTML dashboard for scan results.
 * @author Kevin Matarewicz
 */
export class HtmlReporter {
    /**
     * Builds and saves an HTML dashboard report to the disk.
     * @param report The structured application vulnerability scan report metadata.
     * @param outputPath The file system directory destination path.
     */
    public static generateDashboard(report: ScanReport, outputPath: string): void {
        const fullReportPath = path.join(outputPath, 'security-dashboard.html');

        // Pre-calculate severity distribution metrics for UI components
        const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        report.findings.forEach(f => {
            const sev = f.severity.toUpperCase() as keyof typeof counts;
            if (sev in counts) counts[sev]++;
        });

        const totalFindings = report.findings.length || 1;

        const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web3-Guard Sentinel | Security Dashboard</title>
    <style>
        ${DASHBOARD_STYLES}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Web3-Guard Sentinel Security Compliance Report</h1>
                <div class="timestamp">Target: <strong>${report.targetFile}</strong> &bull; Generated: ${new Date(report.timestamp).toLocaleString()}</div>
            </div>
            <div>
                <span class="badge badge-critical" style="font-size:0.9rem; padding:0.4rem 0.8rem">v1.1.0 Dashboard</span>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div class="card-title">Total Modules Audited</div>
                <div class="card-value">${report.summary.totalDependenciesScanned}</div>
            </div>
            <div class="card" style="border-left: 4px solid var(--critical)">
                <div class="card-title">Critical Threats</div>
                <div class="card-value">${counts.CRITICAL}</div>
            </div>
            <div class="card" style="border-left: 4px solid var(--high)">
                <div class="card-title">High Severity</div>
                <div class="card-value">${counts.HIGH}</div>
            </div>
            <div class="card" style="border-left: 4px solid var(--medium)">
                <div class="card-title">Medium / Low</div>
                <div class="card-value">${counts.MEDIUM + counts.LOW}</div>
            </div>
        </div>

        <div class="severity-breakdown">
            <div class="sev-bar" style="background-color: var(--critical); width: ${(counts.CRITICAL / totalFindings) * 100}%"></div>
            <div class="sev-bar" style="background-color: var(--high); width: ${(counts.HIGH / totalFindings) * 100}%"></div>
            <div class="sev-bar" style="background-color: var(--medium); width: ${(counts.MEDIUM / totalFindings) * 100}%"></div>
            <div class="sev-bar" style="background-color: var(--low); width: ${(counts.LOW / totalFindings) * 100}%"></div>
        </div>

        <div class="findings-section">
            <h2 class="section-title">Identified Vulnerability Log (${report.findings.length} issues)</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%">Severity</th>
                        <th style="width: 25%">Target Component</th>
                        <th style="width: 60%">Vulnerability Details</th>
                    </tr>
                </thead>
                <tbody>
                    ${report.findings.map(f => `
                        <tr>
                            <td>
                                <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                            </td>
                            <td>
                                <strong style="color:#fff">${f.library}</strong>
                                ${f.installedVersion ? `<div style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.25rem">Version: ${f.installedVersion}</div>` : ''}
                            </td>
                            <td>
                                <div style="line-height:1.5; color: #e6edf3">${this.formatDescription(f.description)}</div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>`;

        fs.writeFileSync(fullReportPath, htmlContent, 'utf8');
        console.log(`Report: Interactive HTML Dashboard exported to ${fullReportPath}`);
    }

    private static formatDescription(desc: string): string {
        return desc.replace(/(line \d+|Line \d+)/g, '<span class="code-location">$1</span>');
    }
}