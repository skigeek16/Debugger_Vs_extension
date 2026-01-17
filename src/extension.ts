/**
 * AEGISassist - VS Code Extension
 * 
 * Combines Semgrep static analysis with LLM-powered false positive filtering
 * to deliver high-quality, actionable security findings.
 */

import * as vscode from 'vscode';
import { SemgrepRunner, LLMAnalyzer, DiagnosticManager } from './services';
import { FindingsTreeProvider, StatusBarManager, SecurityCodeActionProvider, FixCodeLensProvider } from './ui';
import {
    ExtensionConfig,
    AnalyzedFinding,
    generateFindingId,
    SemgrepResult
} from './types';

// Global state
let semgrepRunner: SemgrepRunner;
let llmAnalyzer: LLMAnalyzer;
let diagnosticManager: DiagnosticManager;
let treeProvider: FindingsTreeProvider;
let statusBar: StatusBarManager;
let codeActionProvider: SecurityCodeActionProvider;
let codeLensProvider: FixCodeLensProvider;
let outputChannel: vscode.OutputChannel;

// Current findings storage
let currentFindings: AnalyzedFinding[] = [];

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('AEGISassist');
    outputChannel.appendLine('🛡️ AEGISassist is running');

    // Initialize services
    const config = getConfig();

    semgrepRunner = new SemgrepRunner({
        semgrepPath: config.semgrepPath,
        ruleConfig: config.ruleConfig,
        timeout: 300000
    }, outputChannel);

    llmAnalyzer = new LLMAnalyzer(outputChannel);
    llmAnalyzer.configure(config);

    diagnosticManager = new DiagnosticManager(outputChannel);

    // Initialize UI components
    treeProvider = new FindingsTreeProvider();
    statusBar = new StatusBarManager();
    codeActionProvider = new SecurityCodeActionProvider();
    codeLensProvider = new FixCodeLensProvider();

    // Register tree view
    const treeView = vscode.window.createTreeView('aegisAssist.findings', {
        treeDataProvider: treeProvider,
        showCollapseAll: true
    });

    // Register code action provider
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        codeActionProvider,
        { providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds }
    );

    // Register CodeLens provider
    const codeLensDisposable = vscode.languages.registerCodeLensProvider(
        { scheme: 'file' },
        codeLensProvider
    );

    // Register commands
    const scanFileCommand = vscode.commands.registerCommand('aegisAssist.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No file is currently open');
            return;
        }

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'AEGISassist: Scanning current file...',
            cancellable: false
        }, async () => {
            await scanFile(editor.document.uri.fsPath);
        });

        const count = currentFindings.filter(f => !f.dismissed).length;
        if (count > 0) {
            vscode.window.showWarningMessage(`AEGISassist: Found ${count} security issue(s)`);
        } else {
            vscode.window.showInformationMessage('AEGISassist: Scan complete - No issues found!');
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('aegisAssist.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showWarningMessage('No workspace folder is open');
            return;
        }

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'AEGISassist: Scanning workspace...',
            cancellable: false
        }, async () => {
            await scanDirectory(workspaceFolders[0].uri.fsPath);
        });

        const count = currentFindings.filter(f => !f.dismissed).length;
        if (count > 0) {
            vscode.window.showWarningMessage(`AEGISassist: Found ${count} security issue(s) in workspace`);
        } else {
            vscode.window.showInformationMessage('AEGISassist: Workspace scan complete - No issues found!');
        }
    });

    const clearFindingsCommand = vscode.commands.registerCommand('aegisAssist.clearFindings', () => {
        currentFindings = [];
        diagnosticManager.clear();
        treeProvider.clear();
        statusBar.setFindingsCount(0);
        statusBar.setStatus('idle');
        vscode.window.showInformationMessage('AEGISassist: All findings cleared');
    });

    // Fix All command - fixes issues one by one (reliable)
    const fixAllCommand = vscode.commands.registerCommand('aegisAssist.fixAll', async () => {
        if (!llmAnalyzer.isConfigured()) {
            vscode.window.showErrorMessage('LLM not configured. Set up API key in settings.');
            return;
        }

        const activeFindings = currentFindings.filter(f => !f.dismissed);
        if (activeFindings.length === 0) {
            vscode.window.showInformationMessage('No findings to fix.');
            return;
        }

        const confirm = await vscode.window.showWarningMessage(
            `Fix ${activeFindings.length} issues? This will modify your code.`,
            'Fix All',
            'Cancel'
        );

        if (confirm !== 'Fix All') return;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'AEGISassist: Fixing...',
            cancellable: false
        }, async (progress) => {
            let fixed = 0;

            // Sort by file and line (descending) to avoid line number shifts
            const sortedFindings = [...activeFindings].sort((a, b) => {
                if (a.original.path !== b.original.path) {
                    return a.original.path.localeCompare(b.original.path);
                }
                return b.original.start.line - a.original.start.line;
            });

            for (let i = 0; i < sortedFindings.length; i++) {
                const finding = sortedFindings[i];
                progress.report({ message: `${i + 1}/${sortedFindings.length}` });

                try {
                    const uri = vscode.Uri.file(finding.original.path);
                    const document = await vscode.workspace.openTextDocument(uri);

                    const startLine = finding.original.start.line - 1;
                    const endLine = finding.original.end.line - 1;

                    if (startLine >= document.lineCount) continue;

                    const vulnerableRange = new vscode.Range(
                        startLine, 0,
                        endLine, document.lineAt(Math.min(endLine, document.lineCount - 1)).text.length
                    );
                    const vulnerableCode = document.getText(vulnerableRange);

                    const fix = await llmAnalyzer.generateRobustFix(finding.original, vulnerableCode);

                    if (fix && fix.trim().length > 0) {
                        const edit = new vscode.WorkspaceEdit();
                        edit.replace(uri, vulnerableRange, fix);
                        const success = await vscode.workspace.applyEdit(edit);

                        if (success) {
                            finding.dismissed = true;
                            fixed++;
                        }
                    }
                } catch (e) {
                    outputChannel.appendLine(`[FixAll] Error: ${e}`);
                }
            }

            updateUI();
            vscode.window.showInformationMessage(`AEGISassist: Fixed ${fixed}/${activeFindings.length} issues!`);
        });
    });

    const showFindingDetailsCommand = vscode.commands.registerCommand('aegisAssist.showFindingDetails', async (finding: AnalyzedFinding) => {
        await showFindingDetails(finding);
    });

    // Simple navigation to error line
    const goToLineCommand = vscode.commands.registerCommand('aegisAssist.goToLine', async (finding: AnalyzedFinding) => {
        const uri = vscode.Uri.file(finding.original.path);
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(document);

        const line = finding.original.start.line - 1;
        const lineText = document.lineAt(line);
        const range = new vscode.Range(line, 0, line, lineText.text.length);

        editor.selection = new vscode.Selection(range.start, range.end);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    });

    // Show problem details in a popup
    const showProblemCommand = vscode.commands.registerCommand('aegisAssist.showProblem', async (finding: AnalyzedFinding) => {
        const message = finding.original.extra.message;
        const rule = finding.original.check_id;
        const severity = finding.original.extra.severity;

        vscode.window.showWarningMessage(
            `${severity}: ${message}`,
            { modal: false },
            'View Details'
        ).then(action => {
            if (action === 'View Details') {
                showFindingDetails(finding);
            }
        });
    });

    // Robust multi-line fix command
    const fixLineCommand = vscode.commands.registerCommand('aegisAssist.fixLine', async (finding: AnalyzedFinding, uri: vscode.Uri) => {
        if (!llmAnalyzer.isConfigured()) {
            vscode.window.showErrorMessage('LLM not configured. Set up API key in settings.');
            return;
        }

        const document = await vscode.workspace.openTextDocument(uri);

        // Use Semgrep's full range (start line to end line)
        const startLine = finding.original.start.line - 1;
        const endLine = finding.original.end.line - 1;

        // Get the full vulnerable code block
        const vulnerableRange = new vscode.Range(
            startLine, 0,
            endLine, document.lineAt(endLine).text.length
        );
        const vulnerableCode = document.getText(vulnerableRange);

        // Generate fix with progress
        const fix = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Generating secure fix...',
            cancellable: false
        }, async () => {
            return await llmAnalyzer.generateRobustFix(finding.original, vulnerableCode);
        });

        if (!fix) {
            vscode.window.showWarningMessage('Could not generate a fix.');
            return;
        }

        // Show preview before applying
        const preview = await vscode.window.showInformationMessage(
            'Fix generated. Preview before applying?',
            'Apply Fix',
            'Preview',
            'Cancel'
        );

        if (preview === 'Cancel') return;

        if (preview === 'Preview') {
            // Show diff preview
            const originalUri = vscode.Uri.parse(`semgrep-original:${uri.fsPath}?line=${startLine}`);
            const fixedUri = vscode.Uri.parse(`semgrep-fixed:${uri.fsPath}?line=${startLine}`);

            const originalProvider = vscode.workspace.registerTextDocumentContentProvider('semgrep-original', {
                provideTextDocumentContent: () => vulnerableCode
            });
            const fixedProvider = vscode.workspace.registerTextDocumentContentProvider('semgrep-fixed', {
                provideTextDocumentContent: () => fix
            });

            await vscode.commands.executeCommand('vscode.diff', originalUri, fixedUri, 'Vulnerable → Fixed');

            const applyAfterPreview = await vscode.window.showInformationMessage(
                'Apply this fix?',
                'Apply',
                'Cancel'
            );

            originalProvider.dispose();
            fixedProvider.dispose();
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');

            if (applyAfterPreview !== 'Apply') return;
        }

        // Apply the fix
        const edit = new vscode.WorkspaceEdit();
        edit.replace(uri, vulnerableRange, fix);
        await vscode.workspace.applyEdit(edit);

        finding.dismissed = true;
        updateUI();
        vscode.window.showInformationMessage('Fix applied successfully!');
    });

    const markFalsePositiveCommand = vscode.commands.registerCommand('aegisAssist.markFalsePositive', async (finding: AnalyzedFinding) => {
        finding.dismissed = true;
        updateUI();
    });

    const dismissFindingCommand = vscode.commands.registerCommand('aegisAssist.dismissFinding', async (finding: AnalyzedFinding) => {
        finding.dismissed = true;
        updateUI();
    });

    // Show error details inline when clicking from tree
    const showErrorInlineCommand = vscode.commands.registerCommand('aegisAssist.showErrorInline', async (finding: AnalyzedFinding) => {
        const uri = vscode.Uri.file(finding.original.path);
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(document);

        const line = finding.original.start.line - 1;
        const range = new vscode.Range(line, 0, line, document.lineAt(line).text.length);
        editor.selection = new vscode.Selection(range.start, range.end);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    });

    // Apply fix from tree view
    const applyFixFromTreeCommand = vscode.commands.registerCommand('aegisAssist.applyFixFromTree', async (finding: AnalyzedFinding) => {
        const uri = vscode.Uri.file(finding.original.path);
        const document = await vscode.workspace.openTextDocument(uri);

        const line = finding.original.start.line - 1;
        const range = new vscode.Range(line, 0, line, document.lineAt(line).text.length);

        await vscode.commands.executeCommand('aegisAssist.generateFix', finding, uri, range);
    });

    const applyLLMFixCommand = vscode.commands.registerCommand('aegisAssist.applyLLMFix', async (
        finding: AnalyzedFinding,
        uri: vscode.Uri,
        range: vscode.Range
    ) => {
        if (!finding.llmAnalysis?.suggestedFix) {
            vscode.window.showWarningMessage('No AI-suggested fix available');
            return;
        }

        const edit = new vscode.WorkspaceEdit();
        edit.replace(uri, range, finding.llmAnalysis.suggestedFix);
        await vscode.workspace.applyEdit(edit);

        // Mark as fixed
        finding.dismissed = true;
        updateUI();
        vscode.window.showInformationMessage('✅ Fix applied successfully!');
    });

    // Generate and show interactive fix with diff preview
    const generateFixCommand = vscode.commands.registerCommand('aegisAssist.generateFix', async (
        finding: AnalyzedFinding,
        uri: vscode.Uri,
        range: vscode.Range
    ) => {
        if (!llmAnalyzer.isConfigured()) {
            vscode.window.showErrorMessage('LLM not configured. Set up API key in settings.');
            return;
        }

        const fix = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: '🔧 Generating secure fix...',
            cancellable: false
        }, async () => {
            try {
                return await llmAnalyzer.generateFix(finding.original);
            } catch (error) {
                vscode.window.showErrorMessage(`Failed to generate fix: ${error}`);
                return null;
            }
        });

        if (!fix) {
            vscode.window.showWarningMessage('Could not generate a fix for this issue.');
            return;
        }

        // Show interactive diff preview
        await showFixPreview(finding, uri, range, fix);
    });

    // Interactive preview command for comparing fixes
    const previewFixCommand = vscode.commands.registerCommand('aegisAssist.previewFix', async (
        finding: AnalyzedFinding,
        uri: vscode.Uri,
        range: vscode.Range,
        fix: string
    ) => {
        await showFixPreview(finding, uri, range, fix);
    });

    // Listen for configuration changes
    const configChangeDisposable = vscode.workspace.onDidChangeConfiguration(e => {
        if (e.affectsConfiguration('aegisAssist')) {
            const newConfig = getConfig();
            semgrepRunner.updateOptions({
                semgrepPath: newConfig.semgrepPath,
                ruleConfig: newConfig.ruleConfig
            });
            llmAnalyzer.configure(newConfig);
            outputChannel.appendLine('Configuration updated');
        }
    });

    // Listen for file saves (scan on save if enabled)
    const saveDisposable = vscode.workspace.onDidSaveTextDocument(async document => {
        const config = getConfig();
        if (config.scanOnSave) {
            await scanFile(document.uri.fsPath);
        }
    });

    // Register disposables
    context.subscriptions.push(
        outputChannel,
        treeView,
        codeActionDisposable,
        codeLensDisposable,
        scanFileCommand,
        scanWorkspaceCommand,
        clearFindingsCommand,
        fixAllCommand,
        showFindingDetailsCommand,
        goToLineCommand,
        showProblemCommand,
        fixLineCommand,
        markFalsePositiveCommand,
        dismissFindingCommand,
        applyLLMFixCommand,
        generateFixCommand,
        previewFixCommand,
        configChangeDisposable,
        saveDisposable,
        statusBar,
        diagnosticManager
    );

    // Check Semgrep installation
    checkSemgrepInstallation();
}

/**
 * Scan a single file
 */
async function scanFile(filePath: string): Promise<void> {
    statusBar.setStatus('scanning');

    try {
        // Run Semgrep
        const result = await semgrepRunner.scanFile(filePath);

        if (!result.success) {
            statusBar.setStatus('error');
            vscode.window.showErrorMessage(`Semgrep scan failed: ${result.errors.join(', ')}`);
            return;
        }

        // Convert to AnalyzedFinding format
        let newFindings: AnalyzedFinding[] = result.results.map(r => ({
            original: r,
            dismissed: false,
            id: generateFindingId(r),
            discoveredAt: new Date()
        }));

        // Deduplicate findings - keep highest severity per line
        newFindings = deduplicateFindings(newFindings);

        // Analyze with LLM if enabled
        const config = getConfig();
        outputChannel.appendLine(`LLM Provider: ${config.llmProvider}, Configured: ${llmAnalyzer.isConfigured()}, API Key Set: ${config.nebiusApiKey ? 'Yes' : 'No'}`);

        if (config.enableLlmAnalysis && llmAnalyzer.isConfigured() && newFindings.length > 0) {
            statusBar.setStatus('analyzing');
            outputChannel.appendLine('Starting LLM analysis...');
            await analyzeFindingsWithLLM(newFindings, config);
        } else {
            outputChannel.appendLine(`Skipping LLM: enabled=${config.enableLlmAnalysis}, configured=${llmAnalyzer.isConfigured()}`);
        }

        // Merge with existing findings (remove old findings from same file)
        currentFindings = currentFindings.filter(f => f.original.path !== filePath);
        currentFindings.push(...newFindings);

        // Update UI
        updateUI();
        statusBar.setStatus('complete');

        const truePositives = newFindings.filter(f =>
            !f.llmAnalysis || f.llmAnalysis.isTruePositive || f.llmAnalysis.confidence < config.confidenceThreshold
        );

        vscode.window.showInformationMessage(
            `AEGISassist: Found ${result.results.length} findings, ${truePositives.length} likely true positives`
        );

    } catch (error) {
        statusBar.setStatus('error');
        outputChannel.appendLine(`Error: ${error}`);
        vscode.window.showErrorMessage(`AEGISassist error: ${error}`);
    }
}

/**
 * Scan a directory
 */
async function scanDirectory(directoryPath: string): Promise<void> {
    statusBar.setStatus('scanning');
    statusBar.showProgress('Scanning workspace...');

    try {
        const result = await semgrepRunner.scanDirectory(directoryPath);

        if (!result.success) {
            statusBar.setStatus('error');
            vscode.window.showErrorMessage(`Semgrep scan failed: ${result.errors.join(', ')}`);
            return;
        }

        // Convert to AnalyzedFinding format
        let findings: AnalyzedFinding[] = result.results.map(r => ({
            original: r,
            dismissed: false,
            id: generateFindingId(r),
            discoveredAt: new Date()
        }));

        // Deduplicate findings
        currentFindings = deduplicateFindings(findings);

        // Analyze with LLM if enabled
        const config = getConfig();
        if (config.enableLlmAnalysis && llmAnalyzer.isConfigured() && currentFindings.length > 0) {
            statusBar.setStatus('analyzing');
            statusBar.showProgress(`Analyzing ${currentFindings.length} findings with AI...`);
            await analyzeFindingsWithLLM(currentFindings, config);
        }

        // Update UI
        updateUI();
        statusBar.setStatus('complete');

        const truePositives = currentFindings.filter(f =>
            !f.llmAnalysis || f.llmAnalysis.isTruePositive || f.llmAnalysis.confidence < config.confidenceThreshold
        );

        vscode.window.showInformationMessage(
            `AEGISassist: Scanned ${result.filesScanned} files, found ${result.results.length} findings, ${truePositives.length} likely true positives`
        );

    } catch (error) {
        statusBar.setStatus('error');
        outputChannel.appendLine(`Error: ${error}`);
        vscode.window.showErrorMessage(`AEGISassist error: ${error}`);
    }
}

/**
 * Analyze findings with LLM
 */
async function analyzeFindingsWithLLM(findings: AnalyzedFinding[], config: ExtensionConfig): Promise<void> {
    const results = await llmAnalyzer.analyzeFindings(
        findings.map(f => f.original),
        (completed, total) => {
            statusBar.showProgress(`Analyzing findings: ${completed}/${total}`);
        }
    );

    // Attach results to findings
    for (const finding of findings) {
        const key = `${finding.original.path}:${finding.original.start.line}:${finding.original.check_id}`;
        const result = results.get(key);
        if (result) {
            finding.llmAnalysis = result;
        }
    }
}

/**
 * Update all UI components
 */
function updateUI(): void {
    const config = getConfig();

    // Update diagnostics
    diagnosticManager.updateDiagnostics(currentFindings, config.confidenceThreshold);

    // Update tree view
    treeProvider.setFindings(currentFindings);

    // Update code actions
    codeActionProvider.setFindings(currentFindings);

    // Update CodeLens
    codeLensProvider.setFindings(currentFindings);

    // Update status bar count
    const visibleFindings = currentFindings.filter(f => {
        if (f.dismissed) return false;
        if (f.llmAnalysis && !f.llmAnalysis.isTruePositive && f.llmAnalysis.confidence >= config.confidenceThreshold) {
            return false;
        }
        return true;
    });
    statusBar.setFindingsCount(visibleFindings.length);
}

/**
 * Show finding details in a panel
 */
async function showFindingDetails(finding: AnalyzedFinding): Promise<void> {
    const { original, llmAnalysis } = finding;

    // Navigate to the finding location
    const uri = vscode.Uri.file(original.path);
    const document = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(document);

    const range = new vscode.Range(
        original.start.line - 1,
        original.start.col - 1,
        original.end.line - 1,
        original.end.col - 1
    );

    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);

    // Show details in output channel
    outputChannel.show();
    outputChannel.appendLine(`\n=== Finding Details ===`);
    outputChannel.appendLine(`Rule: ${original.check_id}`);
    outputChannel.appendLine(`File: ${original.path}:${original.start.line}`);
    outputChannel.appendLine(`Severity: ${original.extra.severity}`);
    outputChannel.appendLine(`Message: ${original.extra.message}`);

    if (original.extra.metadata.cwe?.length) {
        outputChannel.appendLine(`CWE: ${Array.isArray(original.extra.metadata.cwe) ? original.extra.metadata.cwe.join(', ') : original.extra.metadata.cwe}`);
    }

    if (original.extra.metadata.owasp?.length) {
        outputChannel.appendLine(`OWASP: ${Array.isArray(original.extra.metadata.owasp) ? original.extra.metadata.owasp.join(', ') : original.extra.metadata.owasp}`);
    }

    if (llmAnalysis) {
        outputChannel.appendLine(`\n--- LLM Analysis ---`);
        outputChannel.appendLine(`Verdict: ${llmAnalysis.isTruePositive ? 'TRUE POSITIVE' : 'LIKELY FALSE POSITIVE'}`);
        outputChannel.appendLine(`Confidence: ${llmAnalysis.confidence}%`);
        outputChannel.appendLine(`Reasoning: ${llmAnalysis.reasoning}`);

        if (llmAnalysis.suggestedFix) {
            outputChannel.appendLine(`\nSuggested Fix:\n${llmAnalysis.suggestedFix}`);
        }
    }
}

/**
 * Get extension configuration
 */
function getConfig(): ExtensionConfig {
    const config = vscode.workspace.getConfiguration('aegisAssist');

    return {
        semgrepPath: config.get('semgrepPath', 'semgrep'),
        ruleConfig: config.get('ruleConfig', 'auto'),
        llmProvider: config.get('llmProvider', 'nebius') as ExtensionConfig['llmProvider'],
        openaiApiKey: config.get('openaiApiKey', ''),
        openaiModel: config.get('openaiModel', 'gpt-4o-mini'),
        geminiApiKey: config.get('geminiApiKey', ''),
        ollamaEndpoint: config.get('ollamaEndpoint', 'http://localhost:11434'),
        ollamaModel: config.get('ollamaModel', 'llama3.2'),
        nebiusApiKey: config.get('nebiusApiKey', 'v1.CmQKHHN0YXRpY2tleS1lMDBmZGgxMHdjMzFhZjRnMnMSIXNlcnZpY2VhY2NvdW50LWUwMG44dDRwbWpkZGhua3oxazIMCPjpqMsGELGox6MCOgwI9-zAlgcQwJr7zwNAAloDZTAw.AAAAAAAAAAFxXC1HfyFGSHz34UhqmHSvrNaz5VpAypsgrq2TzkkCRxoVou6FczThTb81dAWyuzVSOf3Wdc0SC1n177_hPoQF'),
        nebiusModel: config.get('nebiusModel', 'moonshotai/Kimi-K2-Thinking'),
        confidenceThreshold: config.get('confidenceThreshold', 70),
        scanOnSave: config.get('scanOnSave', false),
        enableLlmAnalysis: config.get('enableLlmAnalysis', true),
        maxConcurrentAnalysis: config.get('maxConcurrentAnalysis', 5)
    };
}

/**
 * Check if Semgrep is installed
 */
async function checkSemgrepInstallation(): Promise<void> {
    const isInstalled = await semgrepRunner.checkInstallation();

    if (!isInstalled) {
        const action = await vscode.window.showWarningMessage(
            'AEGISassist: Semgrep is not installed or not found in PATH',
            'Install Instructions',
            'Configure Path'
        );

        if (action === 'Install Instructions') {
            vscode.env.openExternal(vscode.Uri.parse('https://semgrep.dev/docs/getting-started/'));
        } else if (action === 'Configure Path') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'aegisAssist.semgrepPath');
        }
    } else {
        outputChannel.appendLine('Semgrep installation verified');
    }
}

/**
 * Show interactive fix preview with diff view
 */
async function showFixPreview(
    finding: AnalyzedFinding,
    uri: vscode.Uri,
    range: vscode.Range,
    fix: string
): Promise<void> {
    // Get the original document
    const document = await vscode.workspace.openTextDocument(uri);
    const originalCode = document.getText(range);

    // Create virtual documents for diff comparison
    const originalUri = vscode.Uri.parse(`semgrep-original:${uri.fsPath}#${range.start.line}`);
    const fixedUri = vscode.Uri.parse(`semgrep-fixed:${uri.fsPath}#${range.start.line}`);

    // Register content providers for virtual documents
    const originalProvider = vscode.workspace.registerTextDocumentContentProvider('semgrep-original', {
        provideTextDocumentContent: () => originalCode
    });
    const fixedProvider = vscode.workspace.registerTextDocumentContentProvider('semgrep-fixed', {
        provideTextDocumentContent: () => fix
    });

    try {
        // Open diff editor
        await vscode.commands.executeCommand('vscode.diff',
            originalUri,
            fixedUri,
            `🔒 Security Fix: ${finding.original.check_id} (Current ↔ Fixed)`
        );

        // Show action buttons
        const action = await vscode.window.showInformationMessage(
            '✨ Review the fix above. Apply it?',
            { modal: false },
            '✅ Apply Fix',
            '❌ Cancel'
        );

        if (action === '✅ Apply Fix') {
            const edit = new vscode.WorkspaceEdit();
            edit.replace(uri, range, fix);
            await vscode.workspace.applyEdit(edit);

            // Mark finding as dismissed
            finding.dismissed = true;
            updateUI();

            vscode.window.showInformationMessage('✅ Secure fix applied successfully!');

            // Close diff editor and go back to the file
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            await vscode.window.showTextDocument(document);
        } else {
            // Just close the diff view
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        }
    } finally {
        originalProvider.dispose();
        fixedProvider.dispose();
    }
}

/**
 * Deduplicate findings - keep only ONE finding per line (highest severity)
 */
function deduplicateFindings(findings: AnalyzedFinding[]): AnalyzedFinding[] {
    const severityRank: Record<string, number> = {
        'ERROR': 4,
        'WARNING': 3,
        'INFO': 2,
        'INVENTORY': 1,
        'EXPERIMENT': 0
    };

    // Group by file:line ONLY (strict - one finding per line)
    const grouped = new Map<string, AnalyzedFinding[]>();

    for (const finding of findings) {
        const key = `${finding.original.path}:${finding.original.start.line}`;

        if (!grouped.has(key)) {
            grouped.set(key, []);
        }
        grouped.get(key)!.push(finding);
    }

    // Keep only the highest severity finding per line
    const deduplicated: AnalyzedFinding[] = [];
    for (const [, group] of grouped) {
        // Sort by severity (highest first)
        group.sort((a, b) => {
            const severityA = severityRank[a.original.extra.severity] || 0;
            const severityB = severityRank[b.original.extra.severity] || 0;
            return severityB - severityA;
        });

        // Keep only the highest severity finding
        deduplicated.push(group[0]);
    }

    return deduplicated;
}

/**
 * Extract vulnerability category from rule ID
 */
function extractVulnCategory(ruleId: string): string {
    // Common patterns: python.lang.security.audit.sql-injection -> sql
    const parts = ruleId.toLowerCase().split(/[.\-_]/);

    // Look for known vulnerability keywords
    const vulnKeywords = [
        'sql', 'injection', 'xss', 'command', 'exec', 'eval', 'pickle',
        'yaml', 'deserialization', 'path', 'traversal', 'ssrf', 'redirect',
        'crypto', 'hash', 'md5', 'sha1', 'secret', 'password', 'key',
        'subprocess', 'shell', 'random', 'template'
    ];

    for (const keyword of vulnKeywords) {
        if (parts.some(p => p.includes(keyword))) {
            return keyword;
        }
    }

    // Fallback to last meaningful part
    return parts.slice(-2).join('-');
}

/**
 * Extension deactivation
 */
export function deactivate() {
    outputChannel?.appendLine('AEGISassist extension deactivated');
}

