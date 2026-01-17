/**
 * Semgrep JSON output type definitions
 * Based on: https://github.com/semgrep/semgrep-interfaces
 */

export interface SemgrepOutput {
    results: SemgrepResult[];
    errors: SemgrepError[];
    paths: {
        scanned: string[];
        skipped?: SkippedPath[];
    };
    version: string;
}

export interface SemgrepResult {
    check_id: string;
    path: string;
    start: SemgrepPosition;
    end: SemgrepPosition;
    extra: SemgrepExtra;
}

export interface SemgrepPosition {
    line: number;
    col: number;
    offset: number;
}

export interface SemgrepExtra {
    message: string;
    severity: SemgrepSeverity;
    metadata: SemgrepMetadata;
    lines: string;
    fingerprint: string;
    is_ignored?: boolean;
    fix?: string;
    fix_regex?: SemgrepFixRegex;
    dataflow_trace?: unknown;
}

export type SemgrepSeverity = 'ERROR' | 'WARNING' | 'INFO' | 'INVENTORY' | 'EXPERIMENT';

export interface SemgrepMetadata {
    category?: string;
    subcategory?: string[];
    technology?: string[];
    cwe?: string[];
    owasp?: string[];
    confidence?: string;
    likelihood?: string;
    impact?: string;
    references?: string[];
    source?: string;
    shortlink?: string;
    'semgrep.dev'?: {
        rule?: {
            url?: string;
        };
    };
    [key: string]: unknown;
}

export interface SemgrepFixRegex {
    regex: string;
    replacement: string;
    count?: number;
}

export interface SemgrepError {
    code: number;
    level: string;
    message: string;
    path?: string;
    spans?: unknown[];
    type: string;
}

export interface SkippedPath {
    path: string;
    reason: string;
}

/**
 * Severity levels mapped to VS Code diagnostic severity
 */
export enum MappedSeverity {
    Error = 0,
    Warning = 1,
    Information = 2,
    Hint = 3
}

/**
 * Map Semgrep severity to VS Code DiagnosticSeverity
 */
export function mapSeverity(severity: SemgrepSeverity): MappedSeverity {
    switch (severity) {
        case 'ERROR':
            return MappedSeverity.Error;
        case 'WARNING':
            return MappedSeverity.Warning;
        case 'INFO':
            return MappedSeverity.Information;
        case 'INVENTORY':
        case 'EXPERIMENT':
        default:
            return MappedSeverity.Hint;
    }
}
