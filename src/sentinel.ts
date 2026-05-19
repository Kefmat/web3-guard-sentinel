import * as path from 'path';
import { ScannerEngine } from './engine/scanner.js';

/**
 * Web3-Guard Sentinel
 * * Main orchestrator context for execution.
 * * @author Kevin Matarewicz
 */
class Sentinel {
    /**
     * Execution initialization.
     */
    public static async main(): Promise<void> {
        console.log("Web3-Guard Sentinel v1.0.0");
        console.log("Status: Initializing security modules...");
        
        const targetPath = path.join(process.cwd(), 'package.json');
        await ScannerEngine.auditDependencies(targetPath);
    }
}

// Execute the application context safely handling promises
Sentinel.main().catch((err) => {
    console.error("Critical Runtime Error: Core engine execution aborted.", err);
});