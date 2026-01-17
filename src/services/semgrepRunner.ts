/**
 * Semgrep Runner Service
 * Executes Semgrep CLI and parses JSON output
 */

import * as vscode from 'vscode';
import { spawn } from 'child_process';
import { SemgrepOutput, SemgrepResult } from '../types';

export interface SemgrepRunnerOptions {
    /** Path to semgrep executable */
    semgrepPath: string;
    /** Rule configuration (e.g., 'auto', 'p/security-audit') */
    ruleConfig: string;
    /** Timeout in milliseconds */
    timeout?: number;
}

export interface RunResult {
    success: boolean;
    results: SemgrepResult[];
    filesScanned: number;
    errors: string[];
    duration: number;
}

export class SemgrepRunner {
    private options: SemgrepRunnerOptions;
    private outputChannel: vscode.OutputChannel;

    constructor(options: SemgrepRunnerOptions, outputChannel: vscode.OutputChannel) {
        this.options = options;
        this.outputChannel = outputChannel;
    }

    /**
     * Check if Semgrep is installed and accessible
     */
    async checkInstallation(): Promise<boolean> {
        return new Promise((resolve) => {
            const process = spawn(this.options.semgrepPath, ['--version']);

            process.on('error', () => {
                resolve(false);
            });

            process.on('close', (code) => {
                resolve(code === 0);
            });
        });
    }

    /**
     * Scan a single file
     */
    async scanFile(filePath: string): Promise<RunResult> {
        return this.runSemgrep([filePath]);
    }

    /**
     * Scan a directory or workspace
     */
    async scanDirectory(directoryPath: string): Promise<RunResult> {
        return this.runSemgrep([directoryPath]);
    }

    /**
     * Scan multiple paths
     */
    async scanPaths(paths: string[]): Promise<RunResult> {
        return this.runSemgrep(paths);
    }

    /**
     * Run Semgrep with given targets
     */
    private async runSemgrep(targets: string[]): Promise<RunResult> {
        const startTime = Date.now();

        return new Promise((resolve) => {
            const args = [
                '--json',
                `--config=${this.options.ruleConfig}`,
                ...targets
            ];

            let stdout = '';
            let stderr = '';

            const process = spawn(this.options.semgrepPath, args, {
                timeout: this.options.timeout || 300000 // 5 minutes default
            });

            process.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            process.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            process.on('error', (error) => {
                resolve({
                    success: false,
                    results: [],
                    filesScanned: 0,
                    errors: [`Failed to run Semgrep: ${error.message}`],
                    duration: Date.now() - startTime
                });
            });

            process.on('close', (code) => {
                const duration = Date.now() - startTime;

                // Semgrep returns 0 for success, 1 for findings found (still success), other codes for errors
                if (code !== 0 && code !== 1) {
                    resolve({
                        success: false,
                        results: [],
                        filesScanned: 0,
                        errors: [`Semgrep exited with code ${code}: ${stderr}`],
                        duration
                    });
                    return;
                }

                try {
                    const output = this.parseOutput(stdout);
                    this.outputChannel.appendLine(`[SemgrepRunner] Found ${output.results.length} findings in ${output.paths.scanned.length} files`);

                    resolve({
                        success: true,
                        results: output.results,
                        filesScanned: output.paths.scanned.length,
                        errors: output.errors.map(e => e.message),
                        duration
                    });
                } catch (parseError) {
                    this.outputChannel.appendLine(`[SemgrepRunner] Parse error: ${parseError}`);
                    this.outputChannel.appendLine(`[SemgrepRunner] Raw output: ${stdout.substring(0, 1000)}...`);

                    resolve({
                        success: false,
                        results: [],
                        filesScanned: 0,
                        errors: [`Failed to parse Semgrep output: ${parseError}`],
                        duration
                    });
                }
            });
        });
    }

    /**
     * Parse Semgrep JSON output
     */
    private parseOutput(stdout: string): SemgrepOutput {
        // Handle empty output
        if (!stdout.trim()) {
            return {
                results: [],
                errors: [],
                paths: { scanned: [] },
                version: 'unknown'
            };
        }

        const output: SemgrepOutput = JSON.parse(stdout);

        // Validate the structure
        if (!Array.isArray(output.results)) {
            output.results = [];
        }
        if (!Array.isArray(output.errors)) {
            output.errors = [];
        }
        if (!output.paths) {
            output.paths = { scanned: [] };
        }

        return output;
    }

    /**
     * Update runner options
     */
    updateOptions(options: Partial<SemgrepRunnerOptions>): void {
        this.options = { ...this.options, ...options };
    }
}
