/**
 * CodeLens Provider - Shows Problem | Fix | Dismiss above errored code
 */

import * as vscode from 'vscode';
import { AnalyzedFinding } from '../types';

export class FixCodeLensProvider implements vscode.CodeLensProvider {
    private findings: AnalyzedFinding[] = [];
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    setFindings(findings: AnalyzedFinding[]): void {
        this.findings = findings;
        this._onDidChangeCodeLenses.fire();
    }

    provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] {
        const codeLenses: vscode.CodeLens[] = [];
        const processedLines = new Set<number>();

        for (const finding of this.findings) {
            if (finding.dismissed) continue;
            if (finding.original.path !== document.uri.fsPath) continue;

            const line = finding.original.start.line - 1;

            // Only one set per line
            if (processedLines.has(line)) continue;
            processedLines.add(line);

            const range = new vscode.Range(line, 0, line, 0);

            // Problem button - shows the issue
            codeLenses.push(new vscode.CodeLens(range, {
                title: 'Problem',
                tooltip: finding.original.extra.message,
                command: 'aegisAssist.showProblem',
                arguments: [finding]
            }));

            // Fix button
            codeLenses.push(new vscode.CodeLens(range, {
                title: 'Fix',
                tooltip: 'Generate and apply secure fix',
                command: 'aegisAssist.fixLine',
                arguments: [finding, document.uri]
            }));

            // Dismiss button
            codeLenses.push(new vscode.CodeLens(range, {
                title: 'Dismiss',
                tooltip: 'Dismiss this finding',
                command: 'aegisAssist.dismissFinding',
                arguments: [finding]
            }));
        }

        return codeLenses;
    }

    dispose(): void {
        this._onDidChangeCodeLenses.dispose();
    }
}
