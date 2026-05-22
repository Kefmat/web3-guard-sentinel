/**
 * Utility for parsing and normalizing Semantic Version (SemVer) strings.
 * Isolates range prefixes to ensure clean compatibility with upstream vulnerability schemas.
 */
export class SemVerUtil {
    /**
     * Extracts a clean, exact version string from common SemVer range definitions.
     * Handles prefixes such as caret (^), tilde (~), and logical inequality symbols.
     * * @param versionRange The raw version string from package.json
     * @returns A sanitized exact version string for API querying.
     */
    public static normalizeVersion(versionRange: string): string {
        if (!versionRange) {
            return '0.0.0';
        }

        // Remove whitespace and handle common placeholders
        let clean = versionRange.trim();
        if (clean === '*' || clean === 'latest') {
            return '0.0.0';
        }

        // Strip caret, tilde, and common comparison prefixes
        clean = clean.replace(/^[\^~>=<]+/, '');

        // Handle logical OR conditions or compound ranges (e.g., ">=1.0.0 <2.0.0")
        // Split by space or comma and take the first valid match
        const parts = clean.split(/[\s,]+/);
        if (parts.length > 0) {
            clean = parts[0];
        }

        // Validate basic SemVer structure (X.Y.Z) using a conservative regex pattern
        const semVerPattern = /^\d+\.\d+\.\d+/;
        const match = clean.match(semVerPattern);

        return match ? match[0] : '0.0.0';
    }
}