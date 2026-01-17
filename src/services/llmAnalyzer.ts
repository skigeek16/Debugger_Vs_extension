/**
 * LLM Analyzer Service
 * Analyzes Semgrep findings using LLM to detect false positives
 */

import * as vscode from 'vscode';
import { SemgrepResult, LLMAnalysisResult, ExtensionConfig, getSeverityLabel } from '../types';

export interface LLMProvider {
    name: string;
    analyze(finding: SemgrepResult, codeContext: string): Promise<LLMAnalysisResult>;
    isConfigured(): boolean;
}

/**
 * OpenAI Provider implementation
 */
export class OpenAIProvider implements LLMProvider {
    name = 'OpenAI';
    private apiKey: string;
    private model: string;

    constructor(apiKey: string, model: string = 'gpt-4o-mini') {
        this.apiKey = apiKey;
        this.model = model;
    }

    isConfigured(): boolean {
        return !!this.apiKey && this.apiKey.length > 0;
    }

    async analyze(finding: SemgrepResult, codeContext: string): Promise<LLMAnalysisResult> {
        const prompt = this.buildPrompt(finding, codeContext);

        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: this.model,
                messages: [
                    { role: 'system', content: this.getSystemPrompt() },
                    { role: 'user', content: prompt }
                ],
                temperature: 0.1,
                response_format: { type: 'json_object' }
            })
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`OpenAI API error: ${response.status} - ${error}`);
        }

        const data = await response.json() as OpenAIResponse;
        const content = data.choices[0]?.message?.content;

        if (!content) {
            throw new Error('Empty response from OpenAI');
        }

        return this.parseResponse(content);
    }

    private getSystemPrompt(): string {
        return `You are an expert security code reviewer. Your task is to analyze security findings from Semgrep static analysis and determine if they are true positives (real security vulnerabilities) or false positives (not actually exploitable or not a real issue in context).

You must respond with a JSON object containing:
- isTruePositive: boolean - true if this is a real security issue, false if it's a false positive
- confidence: number (0-100) - how confident you are in your assessment
- reasoning: string - explain why this is or isn't a real vulnerability
- suggestedFix: string (optional) - if it's a true positive, suggest a fix
- additionalContext: string (optional) - any additional context about the finding

Consider:
1. The actual code context and data flow
2. Whether user input reaches the vulnerable sink
3. Whether there's proper validation/sanitization
4. Framework-specific protections that may be in place
5. Whether the pattern is a common false positive

Be conservative - if unsure, lean towards true positive to avoid missing real vulnerabilities.`;
    }

    private buildPrompt(finding: SemgrepResult, codeContext: string): string {
        const metadata = finding.extra.metadata;

        return `Analyze this security finding:

**Rule ID:** ${finding.check_id}
**Severity:** ${getSeverityLabel(finding.extra.severity)}
**Message:** ${finding.extra.message}
**File:** ${finding.path}
**Line:** ${finding.start.line}

**CWE:** ${Array.isArray(metadata.cwe) ? metadata.cwe.join(', ') : (metadata.cwe || 'N/A')}
**OWASP:** ${Array.isArray(metadata.owasp) ? metadata.owasp.join(', ') : (metadata.owasp || 'N/A')}

**Matched Code:**
\`\`\`
${finding.extra.lines}
\`\`\`

**Surrounding Code Context:**
\`\`\`
${codeContext}
\`\`\`

Is this a true security vulnerability or a false positive? Provide your analysis in JSON format.`;
    }

    private parseResponse(content: string): LLMAnalysisResult {
        try {
            const parsed = JSON.parse(content);
            return {
                isTruePositive: Boolean(parsed.isTruePositive),
                confidence: Math.min(100, Math.max(0, Number(parsed.confidence) || 50)),
                reasoning: String(parsed.reasoning || 'No reasoning provided'),
                suggestedFix: parsed.suggestedFix,
                additionalContext: parsed.additionalContext
            };
        } catch (error) {
            // Fallback if JSON parsing fails
            return {
                isTruePositive: true,
                confidence: 50,
                reasoning: `Failed to parse LLM response: ${content.substring(0, 200)}...`,
                additionalContext: 'Analysis may be incomplete due to parsing error'
            };
        }
    }
}

interface OpenAIResponse {
    choices: Array<{
        message: {
            content: string;
        };
    }>;
}

/**
 * Gemini Provider implementation
 */
export class GeminiProvider implements LLMProvider {
    name = 'Gemini';
    private apiKey: string;

    constructor(apiKey: string) {
        this.apiKey = apiKey;
    }

    isConfigured(): boolean {
        return !!this.apiKey && this.apiKey.length > 0;
    }

    async analyze(finding: SemgrepResult, codeContext: string): Promise<LLMAnalysisResult> {
        const prompt = this.buildPrompt(finding, codeContext);

        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.apiKey}`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: 0.1,
                        responseMimeType: 'application/json'
                    }
                })
            }
        );

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Gemini API error: ${response.status} - ${error}`);
        }

        const data = await response.json() as GeminiResponse;
        const content = data.candidates?.[0]?.content?.parts?.[0]?.text;

        if (!content) {
            throw new Error('Empty response from Gemini');
        }

        return this.parseResponse(content);
    }

    private buildPrompt(finding: SemgrepResult, codeContext: string): string {
        return `You are an expert security code reviewer. Analyze this Semgrep security finding and determine if it's a true positive or false positive.

**Rule ID:** ${finding.check_id}
**Severity:** ${getSeverityLabel(finding.extra.severity)}
**Message:** ${finding.extra.message}
**File:** ${finding.path}
**Line:** ${finding.start.line}

**Matched Code:**
\`\`\`
${finding.extra.lines}
\`\`\`

**Surrounding Code Context:**
\`\`\`
${codeContext}
\`\`\`

Respond with JSON containing:
- isTruePositive: boolean
- confidence: number (0-100)
- reasoning: string
- suggestedFix: string (optional)
- additionalContext: string (optional)`;
    }

    private parseResponse(content: string): LLMAnalysisResult {
        try {
            const parsed = JSON.parse(content);
            return {
                isTruePositive: Boolean(parsed.isTruePositive),
                confidence: Math.min(100, Math.max(0, Number(parsed.confidence) || 50)),
                reasoning: String(parsed.reasoning || 'No reasoning provided'),
                suggestedFix: parsed.suggestedFix,
                additionalContext: parsed.additionalContext
            };
        } catch (error) {
            return {
                isTruePositive: true,
                confidence: 50,
                reasoning: `Failed to parse response: ${content.substring(0, 200)}...`
            };
        }
    }
}

interface GeminiResponse {
    candidates?: Array<{
        content?: {
            parts?: Array<{
                text?: string;
            }>;
        };
    }>;
}

/**
 * Ollama Provider implementation (local LLM)
 */
export class OllamaProvider implements LLMProvider {
    name = 'Ollama';
    private endpoint: string;
    private model: string;

    constructor(endpoint: string = 'http://localhost:11434', model: string = 'llama3.2') {
        this.endpoint = endpoint;
        this.model = model;
    }

    isConfigured(): boolean {
        return !!this.endpoint;
    }

    async analyze(finding: SemgrepResult, codeContext: string): Promise<LLMAnalysisResult> {
        const prompt = this.buildPrompt(finding, codeContext);

        const response = await fetch(`${this.endpoint}/api/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: this.model,
                prompt: prompt,
                stream: false,
                format: 'json'
            })
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Ollama API error: ${response.status} - ${error}`);
        }

        const data = await response.json() as OllamaResponse;

        if (!data.response) {
            throw new Error('Empty response from Ollama');
        }

        return this.parseResponse(data.response);
    }

    private buildPrompt(finding: SemgrepResult, codeContext: string): string {
        return `You are an expert security code reviewer. Analyze this security finding and determine if it's a true positive (real vulnerability) or false positive.

Rule: ${finding.check_id}
Severity: ${getSeverityLabel(finding.extra.severity)}
Message: ${finding.extra.message}
File: ${finding.path}:${finding.start.line}

Matched Code:
${finding.extra.lines}

Context:
${codeContext}

Respond with JSON: {"isTruePositive": boolean, "confidence": 0-100, "reasoning": "explanation", "suggestedFix": "optional fix"}`;
    }

    private parseResponse(content: string): LLMAnalysisResult {
        try {
            const parsed = JSON.parse(content);
            return {
                isTruePositive: Boolean(parsed.isTruePositive),
                confidence: Math.min(100, Math.max(0, Number(parsed.confidence) || 50)),
                reasoning: String(parsed.reasoning || 'No reasoning provided'),
                suggestedFix: parsed.suggestedFix,
                additionalContext: parsed.additionalContext
            };
        } catch (error) {
            return {
                isTruePositive: true,
                confidence: 50,
                reasoning: `Failed to parse response: ${content.substring(0, 200)}...`
            };
        }
    }
}

interface OllamaResponse {
    response: string;
}

/**
 * Nebius Provider implementation (Kimi-K2 model)
 * Uses OpenAI-compatible API
 */
export class NebiusProvider implements LLMProvider {
    name = 'Nebius (Kimi-K2)';
    private apiKey: string;
    private model: string;

    constructor(apiKey: string, model: string = 'moonshotai/Kimi-K2-Thinking') {
        this.apiKey = apiKey;
        this.model = model;
    }

    isConfigured(): boolean {
        return !!this.apiKey && this.apiKey.length > 0;
    }

    async analyze(finding: SemgrepResult, codeContext: string): Promise<LLMAnalysisResult> {
        const prompt = this.buildPrompt(finding, codeContext);

        const response = await fetch('https://api.tokenfactory.nebius.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: this.model,
                messages: [
                    { role: 'system', content: this.getSystemPrompt() },
                    { role: 'user', content: prompt }
                ],
                temperature: 0.1
            })
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Nebius API error: ${response.status} - ${error}`);
        }

        const data = await response.json() as NebiusResponse;
        const content = data.choices?.[0]?.message?.content;

        if (!content) {
            throw new Error('Empty response from Nebius');
        }

        return this.parseResponse(content);
    }

    private getSystemPrompt(): string {
        return `You are an expert security code reviewer. Analyze security findings from Semgrep and determine if they are true positives or false positives.

Respond ONLY with a JSON object (no markdown, no explanation outside JSON):
{
  "isTruePositive": true/false,
  "confidence": 0-100,
  "reasoning": "explanation",
  "suggestedFix": "optional fix code"
}`;
    }

    private buildPrompt(finding: SemgrepResult, codeContext: string): string {
        return `Analyze this security finding:

Rule: ${finding.check_id}
Severity: ${getSeverityLabel(finding.extra.severity)}
Message: ${finding.extra.message}
File: ${finding.path}:${finding.start.line}

Matched Code:
${finding.extra.lines}

Context:
${codeContext}

Is this a real vulnerability or false positive?`;
    }

    private parseResponse(content: string): LLMAnalysisResult {
        try {
            // Try to extract JSON from the response
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            const jsonStr = jsonMatch ? jsonMatch[0] : content;
            const parsed = JSON.parse(jsonStr);
            return {
                isTruePositive: Boolean(parsed.isTruePositive),
                confidence: Math.min(100, Math.max(0, Number(parsed.confidence) || 50)),
                reasoning: String(parsed.reasoning || 'No reasoning provided'),
                suggestedFix: parsed.suggestedFix,
                additionalContext: parsed.additionalContext
            };
        } catch (error) {
            return {
                isTruePositive: true,
                confidence: 50,
                reasoning: content.substring(0, 500)
            };
        }
    }
}

interface NebiusResponse {
    choices?: Array<{
        message?: {
            content?: string;
        };
    }>;
}

/**
 * LLM Analyzer - main class for analyzing findings
 */
export class LLMAnalyzer {
    private provider: LLMProvider | null = null;
    private outputChannel: vscode.OutputChannel;
    private maxConcurrent: number;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
        this.maxConcurrent = 5;
    }

    /**
     * Configure the analyzer with settings
     */
    configure(config: ExtensionConfig): void {
        this.maxConcurrent = config.maxConcurrentAnalysis;

        switch (config.llmProvider) {
            case 'openai':
                this.provider = new OpenAIProvider(config.openaiApiKey, config.openaiModel);
                break;
            case 'gemini':
                this.provider = new GeminiProvider(config.geminiApiKey);
                break;
            case 'ollama':
                this.provider = new OllamaProvider(config.ollamaEndpoint, config.ollamaModel);
                break;
            case 'nebius':
                this.provider = new NebiusProvider(config.nebiusApiKey, config.nebiusModel);
                break;
            default:
                this.provider = null;
        }
    }

    /**
     * Check if the analyzer is properly configured
     */
    isConfigured(): boolean {
        return this.provider?.isConfigured() ?? false;
    }

    /**
     * Analyze a single finding
     */
    async analyzeFinding(finding: SemgrepResult): Promise<LLMAnalysisResult> {
        if (!this.provider || !this.provider.isConfigured()) {
            return {
                isTruePositive: true,
                confidence: 0,
                reasoning: 'LLM analysis not configured. Configure an API key in settings.'
            };
        }

        try {
            // Get code context around the finding
            const codeContext = await this.getCodeContext(finding);

            this.outputChannel.appendLine(`[LLMAnalyzer] Analyzing finding: ${finding.check_id} at ${finding.path}:${finding.start.line}`);

            const result = await this.provider.analyze(finding, codeContext);

            this.outputChannel.appendLine(`[LLMAnalyzer] Result: ${result.isTruePositive ? 'True Positive' : 'False Positive'} (confidence: ${result.confidence}%)`);

            return result;
        } catch (error) {
            this.outputChannel.appendLine(`[LLMAnalyzer] Error analyzing finding: ${error}`);
            return {
                isTruePositive: true,
                confidence: 0,
                reasoning: `Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
            };
        }
    }

    /**
     * Analyze multiple findings with concurrency control
     */
    async analyzeFindings(
        findings: SemgrepResult[],
        onProgress?: (completed: number, total: number) => void
    ): Promise<Map<string, LLMAnalysisResult>> {
        const results = new Map<string, LLMAnalysisResult>();
        const total = findings.length;
        let completed = 0;

        // Process in batches
        for (let i = 0; i < findings.length; i += this.maxConcurrent) {
            const batch = findings.slice(i, i + this.maxConcurrent);

            const batchResults = await Promise.all(
                batch.map(async (finding) => {
                    const result = await this.analyzeFinding(finding);
                    completed++;
                    onProgress?.(completed, total);
                    return { finding, result };
                })
            );

            for (const { finding, result } of batchResults) {
                const key = `${finding.path}:${finding.start.line}:${finding.check_id}`;
                results.set(key, result);
            }
        }

        return results;
    }

    /**
     * Get surrounding code context for a finding
     */
    private async getCodeContext(finding: SemgrepResult): Promise<string> {
        try {
            const uri = vscode.Uri.file(finding.path);
            const document = await vscode.workspace.openTextDocument(uri);

            // Get 10 lines before and after the finding
            const startLine = Math.max(0, finding.start.line - 11);
            const endLine = Math.min(document.lineCount - 1, finding.end.line + 10);

            const lines: string[] = [];
            for (let i = startLine; i <= endLine; i++) {
                const lineNum = i + 1;
                const prefix = lineNum === finding.start.line ? '>>> ' : '    ';
                lines.push(`${prefix}${lineNum.toString().padStart(4)}: ${document.lineAt(i).text}`);
            }

            return lines.join('\n');
        } catch (error) {
            // If we can't read the file, return the matched lines only
            return finding.extra.lines;
        }
    }

    /**
     * Generate a secure fix for a vulnerability
     */
    async generateFix(finding: SemgrepResult): Promise<string | null> {
        if (!this.provider || !this.provider.isConfigured()) {
            return null;
        }

        try {
            const codeContext = await this.getCodeContext(finding);

            const fixPrompt = `You are an expert security engineer fixing vulnerable code.

VULNERABILITY: ${finding.check_id}
ISSUE: ${finding.extra.message}
FILE: ${finding.path}:${finding.start.line}

VULNERABLE LINE:
${finding.extra.lines}

SURROUNDING CODE:
${codeContext}

INSTRUCTIONS:
1. Output ONLY the fixed line(s) that will REPLACE the vulnerable line(s) above
2. The fix must be syntactically correct and compile without errors
3. Preserve the original indentation and code style
4. Do NOT include any explanations, comments about the fix, or markdown formatting
5. Do NOT include code block markers like \`\`\`
6. Output ONLY the corrected code that can directly replace the vulnerable line

FIXED CODE:`;

            // Use the provider to get a fix
            const result = await this.provider.analyze(finding, fixPrompt);

            // If we got a suggested fix, return it
            if (result.suggestedFix) {
                return result.suggestedFix;
            }

            // Otherwise try to extract code from reasoning
            const codeMatch = result.reasoning.match(/```[\w]*\n?([\s\S]*?)\n?```/);
            if (codeMatch) {
                return codeMatch[1].trim();
            }

            return null;
        } catch (error) {
            this.outputChannel.appendLine(`[LLMAnalyzer] Error generating fix: ${error}`);
            return null;
        }
    }

    /**
     * Generate a robust fix for multi-line vulnerabilities
     * Takes the exact vulnerable code block and returns the fixed version
     */
    async generateRobustFix(finding: SemgrepResult, vulnerableCode: string): Promise<string | null> {
        if (!this.provider || !this.provider.isConfigured()) {
            return null;
        }

        try {
            const lines = vulnerableCode.split('\n');
            const lineCount = lines.length;

            // Ultra-strict prompt with clear delimiters
            const fixPrompt = `You are a code fixer. Output ONLY code, no text.

INPUT CODE:
<<<START>>>
${vulnerableCode}
<<<END>>>

SECURITY ISSUE: ${finding.extra.message.slice(0, 150)}

OUTPUT REQUIREMENTS:
- Output the fixed code between <<<FIX>>> and <<<DONE>>> markers
- Output ONLY valid ${this.getLanguage(finding.path)} code
- Keep same line count (${lineCount} lines) if possible
- Keep same indentation
- NO explanations before or after the markers

<<<FIX>>>`;

            this.outputChannel.appendLine(`[Fix] Generating for ${lineCount} line(s)`);

            const result = await this.provider.analyze(finding, fixPrompt);
            let response = result.suggestedFix || result.reasoning || '';

            if (!response || response.length < 5) {
                this.outputChannel.appendLine(`[Fix] Empty response`);
                return null;
            }

            // Extract code between markers
            let fix: string;

            // Try to find FIX/DONE markers
            const markerMatch = response.match(/<<<FIX>>>\s*([\s\S]*?)(?:<<<DONE>>>|$)/i);
            if (markerMatch) {
                fix = markerMatch[1].trim();
            } else {
                // Try markdown code block
                const codeMatch = response.match(/```[\w]*\n?([\s\S]*?)\n?```/);
                if (codeMatch) {
                    fix = codeMatch[1].trim();
                } else {
                    // Use raw response, clean it
                    fix = response.trim()
                        .replace(/^(Here'?s?|The) (fixed|corrected|secure) (code|version):?\s*/i, '')
                        .replace(/<<<DONE>>>.*$/s, '')
                        .replace(/```[\s\S]*$/m, '');
                }
            }

            // Basic validation
            if (!fix || fix.length < 3) {
                this.outputChannel.appendLine(`[Fix] Result too short`);
                return null;
            }

            // Check for garbage (explanation mixed with code)
            const textIndicators = [
                'instead of', 'rather than', 'should be', 'make sure',
                'this fix', 'the fix', 'this code', 'note:', 'explanation:'
            ];

            const hasGarbage = textIndicators.some(t =>
                fix.toLowerCase().includes(t) &&
                !vulnerableCode.toLowerCase().includes(t)
            );

            if (hasGarbage) {
                this.outputChannel.appendLine(`[Fix] Contains explanation text, rejecting`);
                return null;
            }

            // Preserve original indentation
            const originalIndent = vulnerableCode.match(/^(\s*)/)?.[1] || '';
            const fixLines = fix.split('\n');
            const fixIndent = fixLines[0]?.match(/^(\s*)/)?.[1] || '';

            if (originalIndent !== fixIndent && fixLines.length > 0) {
                fix = fixLines.map(line => {
                    if (line.trim() === '') return line;
                    const content = line.replace(/^\s*/, '');
                    const extraIndent = line.match(/^(\s*)/)?.[1]?.slice(fixIndent.length) || '';
                    return originalIndent + extraIndent + content;
                }).join('\n');
            }

            this.outputChannel.appendLine(`[Fix] Success: ${fix.split('\n').length} lines`);
            return fix;

        } catch (error) {
            this.outputChannel.appendLine(`[Fix] Error: ${error}`);
            return null;
        }
    }

    private getLanguage(filePath: string): string {
        const ext = filePath.split('.').pop()?.toLowerCase() || '';
        const langMap: Record<string, string> = {
            'js': 'JavaScript', 'ts': 'TypeScript', 'py': 'Python',
            'java': 'Java', 'rb': 'Ruby', 'go': 'Go', 'php': 'PHP'
        };
        return langMap[ext] || 'code';
    }

    /**
     * Fix all vulnerabilities in a file in ONE API call
     */
    async fixWholeFile(fileContent: string, findings: SemgrepResult[], filePath: string): Promise<string | null> {
        if (!this.provider || !this.provider.isConfigured()) {
            return null;
        }

        if (findings.length === 0) return fileContent;

        try {
            const lineCount = fileContent.split('\n').length;

            // Build concise issue list with line numbers and fix hints
            const issues = findings.map(f => {
                const line = f.start.line;
                const code = f.extra.lines || '';
                const shortId = f.check_id.split('.').pop() || f.check_id;
                return `Line ${line}: ${shortId} - ${f.extra.message.slice(0, 100)}`;
            }).join('\n');

            const fixPrompt = `Fix these security issues in the code. Output ONLY the complete fixed file, nothing else.

ISSUES:
${issues}

CODE (${lineCount} lines):
${fileContent}

OUTPUT THE FIXED FILE (${lineCount} lines, no markdown, no explanation):`;

            this.outputChannel.appendLine(`[LLMAnalyzer] Fixing ${findings.length} issues in ${filePath}`);

            const result = await this.provider.analyze(findings[0], fixPrompt);

            let fixed = result.suggestedFix || result.reasoning || '';

            if (!fixed || fixed.trim().length < fileContent.length * 0.3) {
                this.outputChannel.appendLine(`[LLMAnalyzer] Response too short or empty`);
                return null;
            }

            // Clean LLM artifacts
            fixed = fixed.trim()
                .replace(/^```[\w]*\n?/g, '')
                .replace(/\n?```$/g, '')
                .replace(/^OUTPUT THE FIXED FILE.*?\n/i, '')
                .replace(/^Here'?s? (?:is )?the fixed (?:code|file):?\s*\n?/i, '');

            const fixedLines = fixed.split('\n').length;
            this.outputChannel.appendLine(`[LLMAnalyzer] Result: ${lineCount} → ${fixedLines} lines`);

            // Reject if significantly different
            if (fixedLines < lineCount * 0.5 || fixedLines > lineCount * 2) {
                this.outputChannel.appendLine(`[LLMAnalyzer] Line count mismatch, rejecting`);
                return null;
            }

            return fixed;

        } catch (error) {
            this.outputChannel.appendLine(`[LLMAnalyzer] Error: ${error}`);
            return null;
        }
    }
}
