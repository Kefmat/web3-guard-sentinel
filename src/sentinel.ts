import { ScannerEngine } from './engine/scanner.js';

/**
 * Web3-Guard Sentinel
 * * Main orchestrator context for execution.
 * * @author Kevin Matarewicz
 */
class Sentinel {
    /**
     * Parse system arguments and initialize execution.
     */
    public static async main(): Promise<void> {
        console.log("Web3-Guard Sentinel v1.0.0");
        console.log("Status: Initializing security modules...");

        const args = process.argv.slice(2);
        
        // Extract named parameters from terminal array strings
        const pathIndex = args.indexOf('--path');
        const failIndex = args.indexOf('--fail-on');

        const targetDirectory = (pathIndex !== -1 && args[pathIndex + 1]) ? args[pathIndex + 1]! : process.cwd();
        const failThreshold = (failIndex !== -1 && args[failIndex + 1]) ? args[failIndex + 1]! : null;

        if (failThreshold) {
            console.log(`Config: Policy enforcement active. Failing on severities >= ${failThreshold.toUpperCase()}`);
        }

        await ScannerEngine.auditDependencies(targetDirectory, failThreshold);
    }
}

Sentinel.main().catch((err) => {
    console.error("Critical Runtime Error: Core engine execution aborted.", err);
});