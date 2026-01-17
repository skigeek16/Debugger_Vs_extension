# AEGISassist 🛡️

**AI-powered security vulnerability scanner and fixer for VS Code** - Combines Semgrep static analysis with LLM-based vulnerability fixing.

![VS Code](https://img.shields.io/badge/VS%20Code-1.85+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- 🔍 **Semgrep Integration** - Run Semgrep static analysis directly from VS Code
- 🤖 **AI-Powered Fixes** - Uses LLM to automatically fix security vulnerabilities
- 🎯 **One-Click Fix** - Fix individual issues or all issues at once
- 📝 **Rich Diagnostics** - Findings appear in Problems panel with inline highlights
- 🌳 **Tree View** - Browse findings organized by file and severity
- ⚡ **CodeLens Actions** - Problem | Fix | Dismiss buttons above vulnerable code

## Requirements

- **Semgrep CLI** installed:
  ```bash
  # macOS
  brew install semgrep
  
  # pip (any platform)
  pip install semgrep
  ```

- **LLM API Key** (for AI-powered fixes):
  - OpenAI API key, or
  - Google Gemini API key, or
  - Nebius API key, or
  - Local Ollama installation

## Quick Start

1. Install the extension
2. Open a project in VS Code
3. Click the **file icon** in AEGISassist sidebar to scan current file
4. View findings in the sidebar or Problems panel
5. Click **Fix** to auto-fix vulnerabilities

## Commands

| Command | Description |
|---------|-------------|
| `AEGISassist: Scan Current File` | Scan the active file |
| `AEGISassist: Scan Workspace` | Scan entire workspace |
| `AEGISassist: Fix All` | Fix all detected issues |
| `AEGISassist: Clear All Findings` | Clear all findings |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `aegisAssist.semgrepPath` | `semgrep` | Path to Semgrep executable |
| `aegisAssist.ruleConfig` | `auto` | Semgrep rule config |
| `aegisAssist.llmProvider` | `nebius` | LLM provider |
| `aegisAssist.confidenceThreshold` | `70` | Min confidence to show findings |
| `aegisAssist.scanOnSave` | `false` | Auto-scan on file save |

### LLM Providers

**OpenAI:**
```json
{
  "aegisAssist.llmProvider": "openai",
  "aegisAssist.openaiApiKey": "sk-..."
}
```

**Nebius (Default):**
```json
{
  "aegisAssist.llmProvider": "nebius",
  "aegisAssist.nebiusApiKey": "..."
}
```

**Ollama (Local, Free):**
```bash
ollama pull llama3.2
```
```json
{
  "aegisAssist.llmProvider": "ollama",
  "aegisAssist.ollamaEndpoint": "http://localhost:11434"
}
```

## How It Works

1. **Semgrep scans** your code for security vulnerabilities
2. **Findings displayed** in sidebar and Problems panel
3. **LLM generates** fixes for each vulnerability
4. **One-click apply** to fix issues

## Development

```bash
npm install
npm run compile
# Press F5 to launch Extension Host
```

## License

MIT
