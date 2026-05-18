import * as path from 'path';
import { ScannerEngine } from './engine/scanner.js';

/**
 * Web3-Guard Sentinel
 * * Main orchestrator context for execution.
 * * @author Kefmat
 */
class Sentinel {
    /**
     * Execution initialization.
     */
    public static main(): void {
        console.log("Web3-Guard Sentinel v1.0.0");
        console.log("Status: Initializing security modules...");
        
        const targetPath = path.join(process.cwd(), 'package.json');
        ScannerEngine.auditDependencies(targetPath);
    }
}

Sentinel.main();