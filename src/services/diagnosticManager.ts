/**
 * Diagnostic Manager
 * Manages VS Code diagnostics for security findings
 */

import * as vscode from 'vscode';
import { AnalyzedFinding, mapSeverity, SemgrepSeverity, getSeverityLabel } from '../types';

export class DiagnosticManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private outputChannel: vscode.OutputChannel;

    constructor(outputChannel: vscode.OutputChannel) {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('aegisAssist');
        this.outputChannel = outputChannel;
    }

    /**
     * Update diagnostics for a set of findings
     */
    updateDiagnostics(findings: AnalyzedFinding[], confidenceThreshold: number): void {
        // Clear existing diagnostics
        this.diagnosticCollection.clear();

        // Group findings by file
        const findingsByFile = new Map<string, AnalyzedFinding[]>();

        for (const finding of findings) {
            // Skip dismissed findings
            if (finding.dismissed) {
                continue;
            }

            // Skip low-confidence findings (if LLM analysis available)
            if (finding.llmAnalysis && !finding.llmAnalysis.isTruePositive) {
                if (finding.llmAnalysis.confidence >= confidenceThreshold) {
                    // High confidence false positive - skip
                    continue;
                }
            }

            const filePath = finding.original.path;
            if (!findingsByFile.has(filePath)) {
                findingsByFile.set(filePath, []);
            }
            findingsByFile.get(filePath)!.push(finding);
        }

        // Create diagnostics for each file
        for (const [filePath, fileFindings] of findingsByFile) {
            const uri = vscode.Uri.file(filePath);
            const diagnostics = fileFindings.map(finding => this.createDiagnostic(finding));
            this.diagnosticCollection.set(uri, diagnostics);
        }
    }

    /**
     * Create a diagnostic from a finding
     */
    private createDiagnostic(finding: AnalyzedFinding): vscode.Diagnostic {
        const { original, llmAnalysis } = finding;

        // Create range (VS Code uses 0-indexed lines)
        const range = new vscode.Range(
            original.start.line - 1,
            original.start.col - 1,
            original.end.line - 1,
            original.end.col - 1
        );

        // Build message
        let message = original.extra.message;

        // Add LLM analysis info if available
        if (llmAnalysis) {
            const confidenceLabel = llmAnalysis.confidence >= 80 ? '🔴' :
                llmAnalysis.confidence >= 50 ? '🟡' : '🟢';
            message += `\n\n${confidenceLabel} LLM Analysis (${llmAnalysis.confidence}% confidence):\n${llmAnalysis.reasoning}`;

            if (llmAnalysis.suggestedFix) {
                message += `\n\n💡 Suggested Fix:\n${llmAnalysis.suggestedFix}`;
            }
        }

        // Map severity
        const severity = this.mapToVSCodeSeverity(original.extra.severity);

        const diagnostic = new vscode.Diagnostic(range, message, severity);

        // Add metadata
        diagnostic.code = {
            value: original.check_id,
            target: this.getRuleUrl(original)
        };
        diagnostic.source = 'AEGISassist';

        // Add related information if we have CWE/OWASP data
        const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];

        if (original.extra.metadata.cwe?.length) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(vscode.Uri.file(original.path), range),
                `CWE: ${Array.isArray(original.extra.metadata.cwe) ? original.extra.metadata.cwe.join(', ') : original.extra.metadata.cwe}`
            ));
        }

        if (original.extra.metadata.owasp?.length) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(vscode.Uri.file(original.path), range),
                `OWASP: ${Array.isArray(original.extra.metadata.owasp) ? original.extra.metadata.owasp.join(', ') : original.extra.metadata.owasp}`
            ));
        }

        if (relatedInfo.length > 0) {
            diagnostic.relatedInformation = relatedInfo;
        }

        // Add tags for deprecation or unnecessary code if applicable
        if (original.extra.severity === 'INFO' || original.extra.severity === 'INVENTORY') {
            diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
        }

        return diagnostic;
    }

    /**
     * Map Semgrep severity to VS Code DiagnosticSeverity
     */
    private mapToVSCodeSeverity(severity: SemgrepSeverity): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'ERROR':
                return vscode.DiagnosticSeverity.Error;
            case 'WARNING':
                return vscode.DiagnosticSeverity.Warning;
            case 'INFO':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    /**
     * Get rule documentation URL
     */
    private getRuleUrl(finding: AnalyzedFinding['original']): vscode.Uri {
        const ruleUrl = finding.extra.metadata['semgrep.dev']?.rule?.url ||
            finding.extra.metadata.shortlink ||
            `https://semgrep.dev/r?q=${encodeURIComponent(finding.check_id)}`;
        return vscode.Uri.parse(ruleUrl);
    }

    /**
     * Clear all diagnostics
     */
    clear(): void {
        this.diagnosticCollection.clear();
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
