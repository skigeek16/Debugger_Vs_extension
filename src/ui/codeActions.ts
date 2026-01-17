/**
 * Code Actions Provider - Single Apply Fix option
 */

import * as vscode from 'vscode';
import { AnalyzedFinding } from '../types';

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    private findings: Map<string, AnalyzedFinding> = new Map();

    setFindings(findings: AnalyzedFinding[]): void {
        this.findings.clear();
        for (const finding of findings) {
            const key = `${finding.original.path}:${finding.original.start.line}`;
            this.findings.set(key, finding);
        }
    }

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] | undefined {
        const actions: vscode.CodeAction[] = [];

        const semgrepDiagnostics = context.diagnostics.filter(d => d.source === 'AEGISassist');

        for (const diagnostic of semgrepDiagnostics) {
            const key = `${document.uri.fsPath}:${diagnostic.range.start.line + 1}`;
            let finding = this.findings.get(key);

            if (!finding) {
                for (const [, f] of this.findings) {
                    if (f.original.start.line === diagnostic.range.start.line + 1) {
                        finding = f;
                        break;
                    }
                }
            }

            if (!finding) continue;

            // Single option: Apply Fix
            const applyFix = new vscode.CodeAction(
                'Apply Fix',
                vscode.CodeActionKind.QuickFix
            );
            applyFix.isPreferred = true;
            applyFix.command = {
                command: 'aegisAssist.generateFix',
                title: 'Apply Fix',
                arguments: [finding, document.uri, diagnostic.range]
            };
            applyFix.diagnostics = [diagnostic];
            actions.push(applyFix);
        }

        return actions;
    }
}
