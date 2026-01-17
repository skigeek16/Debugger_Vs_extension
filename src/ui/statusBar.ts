/**
 * Status Bar Manager
 * Displays scan status and quick actions in VS Code status bar
 */

import * as vscode from 'vscode';
import { ScanStatus } from '../types';

export class StatusBarManager {
    private statusBarItem: vscode.StatusBarItem;
    private scanStatus: ScanStatus = 'idle';
    private findingsCount: number = 0;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        this.statusBarItem.name = 'AEGISassist';
        this.statusBarItem.command = 'aegisAssist.scanFile';
        this.update();
        this.statusBarItem.show();
    }

    /**
     * Update the status bar based on scan status
     */
    setStatus(status: ScanStatus): void {
        this.scanStatus = status;
        this.update();
    }

    /**
     * Update the findings count display
     */
    setFindingsCount(count: number): void {
        this.findingsCount = count;
        this.update();
    }

    /**
     * Show scanning progress
     */
    showProgress(message: string): void {
        this.statusBarItem.text = `$(sync~spin) ${message}`;
        this.statusBarItem.backgroundColor = undefined;
    }

    private update(): void {
        switch (this.scanStatus) {
            case 'idle':
                this.statusBarItem.text = '$(shield) AEGISassist';
                this.statusBarItem.tooltip = 'Click to scan current file';
                this.statusBarItem.backgroundColor = undefined;
                break;

            case 'scanning':
                this.statusBarItem.text = '$(sync~spin) Scanning...';
                this.statusBarItem.tooltip = 'Semgrep is analyzing your code';
                this.statusBarItem.backgroundColor = undefined;
                break;

            case 'analyzing':
                this.statusBarItem.text = '$(sync~spin) Analyzing with AI...';
                this.statusBarItem.tooltip = 'LLM is analyzing findings for false positives';
                this.statusBarItem.backgroundColor = undefined;
                break;

            case 'complete':
                if (this.findingsCount === 0) {
                    this.statusBarItem.text = '$(shield-check) No issues';
                    this.statusBarItem.tooltip = 'No security issues found';
                    this.statusBarItem.backgroundColor = undefined;
                } else {
                    this.statusBarItem.text = `$(shield-x) ${this.findingsCount} issue${this.findingsCount === 1 ? '' : 's'}`;
                    this.statusBarItem.tooltip = `Found ${this.findingsCount} security issue(s). Click to scan again.`;
                    this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                }
                break;

            case 'error':
                this.statusBarItem.text = '$(error) Scan failed';
                this.statusBarItem.tooltip = 'Click to try again';
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                break;
        }
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        this.statusBarItem.dispose();
    }
}
