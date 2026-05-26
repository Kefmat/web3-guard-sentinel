import { parseArgs } from 'util';
import { ScannerEngine } from './engine/scanner.js';

/**
 * Web3-Guard Sentinel
 * * Main orchestrator context for execution. Handles CLI processing and bootstrap flows.
 * * @author Kevin Matarewicz
 */
class Sentinel {
    /**
     * Parse system arguments using native Node.js util parser and initialize execution.
     */
    public static async main(): Promise<void> {
        console.log("=================================================");
        console.log("          Web3-Guard Sentinel v1.1.0            ");
        console.log("=================================================");
        console.log("Status: Initializing security modules...");

        const options = {
            dir: { type: 'string' as const },
            'fail-on': { type: 'string' as const }
        };

        try {
            const { values } = parseArgs({ args: process.argv.slice(2), options, strict: false });

            // Ensure targetDirectory is always treated as a single clean string value
            const targetDirectory = typeof values['dir'] === 'string' ? values['dir'] : process.cwd();
            
            // Type guard to filter out boolean flags that lack real value strings
            const failThreshold = typeof values['fail-on'] === 'string' ? values['fail-on'] : null;

            if (failThreshold) {
                console.log(`Config: Policy enforcement active. Failing on severities >= ${failThreshold.toUpperCase()}`);
            }

            // Dispatch execution context directly to the transitive dependency engine
            await ScannerEngine.auditDependencies(targetDirectory, failThreshold);

        } catch (error) {
            console.error("Critical Runtime Error: Failed to parse execution arguments accurately.");
            process.exit(1);
        }
    }
}

Sentinel.main().catch((err) => {
    console.error("Critical Runtime Error: Core engine execution aborted.", err);
    process.exit(1);
});