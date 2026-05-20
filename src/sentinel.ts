import { parseArgs } from 'util';
import { ScannerEngine } from './engine/scanner.js';

/**
 * Web3-Guard Sentinel
 * * Main orchestrator context for execution.
 * * @author Kevin Matarewicz
 */
class Sentinel {
    /**
     * Parse system arguments using native Node.js util parser and initialize execution.
     */
    public static async main(): Promise<void> {
        console.log("Web3-Guard Sentinel v1.0.0");
        console.log("Status: Initializing security modules...");

        const options = {
            path: { type: 'string' as const },
            'fail-on': { type: 'string' as const }
        };

        try {
            const { values } = parseArgs({ args: process.argv.slice(2), options, strict: false });

            // Ensure targetDirectory is always treated as a single string string value
            const targetDirectory = typeof values['path'] === 'string' ? values['path'] : process.cwd();
            
            // Type guard to filter out boolean 'true' flags that lack values
            const failThreshold = typeof values['fail-on'] === 'string' ? values['fail-on'] : null;

            if (failThreshold) {
                console.log(`Config: Policy enforcement active. Failing on severities >= ${failThreshold.toUpperCase()}`);
            }

            await ScannerEngine.auditDependencies(targetDirectory, failThreshold);

        } catch (error) {
            console.error("Critical Runtime Error: Failed to parse execution arguments accurately.");
            process.exit(1);
        }
    }
}

Sentinel.main().catch((err) => {
    console.error("Critical Runtime Error: Core engine execution aborted.", err);
});