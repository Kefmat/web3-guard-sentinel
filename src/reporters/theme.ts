/**
 * Stylesheet context for the Web3-Guard Sentinel HTML reporting subsystem.
 * Houses the presentation layouts and design tokens separate from structural generation logic.
 * @author Kevin Matarewicz
 */
export const DASHBOARD_STYLES = `
:root {
    --bg-main: #0d1117;
    --bg-card: #161b22;
    --border: #30363d;
    --text-primary: #c9d1d9;
    --text-secondary: #8b949e;
    --critical: #f85149;
    --high: #ff964f;
    --medium: #e3b341;
    --low: #58a6ff;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    margin: 0;
    padding: 2rem;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
}
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
}
h1 { margin: 0; font-size: 1.75rem; font-weight: 600; color: #fff; }
.timestamp { color: var(--text-secondary); font-size: 0.875rem; }

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}
.card {
    background-color: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.25rem;
}
.card-title { font-size: 0.85rem; color: var(--text-secondary); font-weight: 500; text-transform: uppercase; }
.card-value { font-size: 2rem; font-weight: 600; margin-top: 0.5rem; color: #fff; }

.severity-breakdown {
    display: flex;
    height: 12px;
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 2.5rem;
    background: #21262d;
}
.sev-bar { height: 100%; transition: width 0.3s ease; }

.findings-section {
    background-color: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
}
.section-title {
    padding: 1rem 1.25rem;
    font-size: 1.1rem;
    font-weight: 600;
    border-bottom: 1px solid var(--border);
    margin: 0;
    background-color: #1f242c;
}
table { width: 100%; border-collapse: collapse; text-align: left; }
th { background-color: #1f242c; color: var(--text-secondary); font-weight: 500; font-size: 0.85rem; padding: 0.75rem 1.25rem; border-bottom: 1px solid var(--border); }
td { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; vertical-align: top; }
tr:last-child td { border-bottom: none; }

.badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    font-size: 0.75rem;
    font-weight: 600;
    border-radius: 20px;
    text-transform: uppercase;
}
.badge-critical { background: rgba(248, 81, 73, 0.15); color: var(--critical); border: 1px solid rgba(248, 81, 73, 0.3); }
.badge-high { background: rgba(255, 150, 79, 0.15); color: var(--high); border: 1px solid rgba(255, 150, 79, 0.3); }
.badge-medium { background: rgba(227, 179, 65, 0.15); color: var(--medium); border: 1px solid rgba(227, 179, 65, 0.3); }
.badge-low { background: rgba(88, 166, 255, 0.15); color: var(--low); border: 1px solid rgba(88, 166, 255, 0.3); }

.code-location { font-family: monospace; background: #21262d; padding: 0.2rem 0.4rem; border-radius: 4px; color: #ff79c6; }
`;