import { VulnerabilityRule } from '../types/security.js';

/**
 * Reference database for known insecure Web3 package dependencies.
 */
export const VULNERABILITY_REGISTRY: Record<string, VulnerabilityRule> = {
    'ethers': {
        versionRange: '<5.7.0',
        severity: 'HIGH',
        description: 'Potential padding oracle vulnerability in cryptographic decryption routines.'
    },
    'web3': {
        versionRange: '<1.8.0',
        severity: 'CRITICAL',
        description: 'Insecure handling of private keys during local wallet creation.'
    }
};