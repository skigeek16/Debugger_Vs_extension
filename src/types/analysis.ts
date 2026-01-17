/**
 * Analysis types for LLM-processed findings
 */

import { SemgrepResult, SemgrepSeverity, MappedSeverity } from './semgrep';

/**
 * Result of LLM analysis on a finding
 */
export interface LLMAnalysisResult {
    /** Whether the LLM believes this is a true positive */
    isTruePositive: boolean;
    /** Confidence score from 0-100 */
    confidence: number;
    /** Explanation of the analysis */
    reasoning: string;
    /** Suggested fix if available */
    suggestedFix?: string;
    /** Additional context about the vulnerability */
    additionalContext?: string;
}

/**
 * A Semgrep finding enhanced with LLM analysis
 */
export interface AnalyzedFinding {
    /** Original Semgrep result */
    original: SemgrepResult;
    /** LLM analysis result (undefined if not analyzed yet) */
    llmAnalysis?: LLMAnalysisResult;
    /** Whether this finding has been dismissed by the user */
    dismissed: boolean;
    /** User-added notes */
    userNotes?: string;
    /** Unique identifier for this finding */
    id: string;
    /** Timestamp when finding was discovered */
    discoveredAt: Date;
}

/**
 * Status of the scan operation
 */
export type ScanStatus = 'idle' | 'scanning' | 'analyzing' | 'complete' | 'error';

/**
 * Overall scan result
 */
export interface ScanResult {
    /** Status of the scan */
    status: ScanStatus;
    /** All findings, both analyzed and unanalyzed */
    findings: AnalyzedFinding[];
    /** Total files scanned */
    filesScanned: number;
    /** Total rules applied */
    rulesApplied: number;
    /** Duration of the scan in milliseconds */
    duration: number;
    /** Error message if scan failed */
    error?: string;
    /** Timestamp when scan started */
    startedAt: Date;
    /** Timestamp when scan completed */
    completedAt?: Date;
}

/**
 * Configuration for the extension
 */
export interface ExtensionConfig {
    semgrepPath: string;
    ruleConfig: string;
    llmProvider: 'openai' | 'gemini' | 'ollama' | 'nebius';
    openaiApiKey: string;
    openaiModel: string;
    geminiApiKey: string;
    ollamaEndpoint: string;
    ollamaModel: string;
    nebiusApiKey: string;
    nebiusModel: string;
    confidenceThreshold: number;
    scanOnSave: boolean;
    enableLlmAnalysis: boolean;
    maxConcurrentAnalysis: number;
}

/**
 * Finding grouped by file for tree view
 */
export interface FileFindings {
    filePath: string;
    findings: AnalyzedFinding[];
    highestSeverity: MappedSeverity;
}

/**
 * Generate a unique ID for a finding
 */
export function generateFindingId(result: SemgrepResult): string {
    return `${result.path}:${result.start.line}:${result.check_id}:${result.extra.fingerprint}`;
}


/**
 * Get human-readable severity label
 */
export function getSeverityLabel(severity: SemgrepSeverity): string {
    switch (severity) {
        case 'ERROR':
            return 'Critical';
        case 'WARNING':
            return 'High';
        case 'INFO':
            return 'Medium';
        case 'INVENTORY':
            return 'Low';
        case 'EXPERIMENT':
            return 'Experimental';
        default:
            return 'Unknown';
    }
}
