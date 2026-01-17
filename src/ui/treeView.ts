/**
 * Tree View Provider for Security Findings
 * Simple flat list - click to navigate to error line
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { AnalyzedFinding, getSeverityLabel, MappedSeverity, mapSeverity } from '../types';

type TreeItemType = 'file' | 'finding';

export class FindingsTreeProvider implements vscode.TreeDataProvider<FindingTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<FindingTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private findings: AnalyzedFinding[] = [];

    setFindings(findings: AnalyzedFinding[]): void {
        this.findings = findings.filter(f => !f.dismissed);
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.findings = [];
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: FindingTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FindingTreeItem): FindingTreeItem[] {
        if (!element) {
            return this.getFileGroups();
        } else if (element.type === 'file') {
            return this.getFindingsForFile(element.data?.filePath || '');
        }
        return [];
    }

    private getFileGroups(): FindingTreeItem[] {
        const groups = new Map<string, AnalyzedFinding[]>();

        for (const finding of this.findings) {
            const filePath = finding.original.path;
            if (!groups.has(filePath)) {
                groups.set(filePath, []);
            }
            groups.get(filePath)!.push(finding);
        }

        return Array.from(groups.entries()).map(([filePath, findings]) => {
            const highestSeverity = findings.reduce((highest, f) => {
                const sev = mapSeverity(f.original.extra.severity);
                return sev < highest ? sev : highest;
            }, MappedSeverity.Hint);

            return new FindingTreeItem(
                path.basename(filePath),
                `${findings.length} issues`,
                vscode.TreeItemCollapsibleState.Expanded,
                'file',
                this.getSeverityIcon(highestSeverity),
                { filePath, findings }
            );
        });
    }

    private getFindingsForFile(filePath: string): FindingTreeItem[] {
        return this.findings
            .filter(f => f.original.path === filePath)
            .map(finding => {
                const severity = mapSeverity(finding.original.extra.severity);

                return new FindingTreeItem(
                    `Line ${finding.original.start.line}: ${this.getShortMessage(finding.original.extra.message)}`,
                    getSeverityLabel(finding.original.extra.severity),
                    vscode.TreeItemCollapsibleState.None,
                    'finding',
                    this.getSeverityIcon(severity),
                    { finding },
                    {
                        command: 'aegisAssist.goToLine',
                        title: 'Go to Line',
                        arguments: [finding]
                    }
                );
            });
    }

    private getShortMessage(message: string): string {
        return message.length > 50 ? message.substring(0, 47) + '...' : message;
    }

    private getSeverityIcon(severity: MappedSeverity): vscode.ThemeIcon {
        switch (severity) {
            case MappedSeverity.Error:
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case MappedSeverity.Warning:
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            default:
                return new vscode.ThemeIcon('info');
        }
    }
}

class FindingTreeItem extends vscode.TreeItem {
    constructor(
        label: string,
        description: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly type: TreeItemType,
        iconPath: vscode.ThemeIcon,
        public readonly data?: {
            filePath?: string;
            findings?: AnalyzedFinding[];
            finding?: AnalyzedFinding;
        },
        command?: vscode.Command
    ) {
        super(label, collapsibleState);
        this.description = description;
        this.iconPath = iconPath;
        this.contextValue = type;
        if (command) {
            this.command = command;
        }

        // Add tooltip for findings
        if (type === 'finding' && data?.finding) {
            this.tooltip = data.finding.original.extra.message;
        }
    }
}
