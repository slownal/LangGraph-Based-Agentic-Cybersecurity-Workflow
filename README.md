# Agentic Cybersecurity Pipeline

An autonomous cybersecurity assessment tool that leverages LangChain and local LLMs to perform automated security scanning and analysis.

##  Features

- **Autonomous Task Planning**: Automatically breaks down high-level security instructions into executable tasks
- **Scope-Aware Scanning**: Enforces defined target scope for all security operations
- **Dynamic Task Management**: Adapts and creates new tasks based on scan results
- **Multiple Security Tools Integration**:
  - Nmap for port scanning
  - Gobuster for directory enumeration
  - FFuf for web fuzzing
- **Intelligent Analysis**: Uses LLMs to analyze results and suggest further actions
- **Comprehensive Reporting**: Generates detailed reports of findings and scan summary

## 🛠️ Prerequisites

- Python 3.11+
- Ollama (for local LLM support)
- Security Tools:
  - Nmap
  - Gobuster
  - FFuf

### Windows Installation

1. **Install Python 3.11+**
   - Download from [Python.org](https://www.python.org/downloads/)
   - Ensure "Add Python to PATH" is checked during installation

2. **Install Ollama**
   ```bash
   # Download and install from
   https://ollama.ai/download/windows
   
   # Pull the Mistral model
   ollama pull mistral
   ```

3. **Install Security Tools**
   - Create directory: `C:\SecurityTools`
   - Download and add to `C:\SecurityTools`:
     - [Nmap](https://nmap.org/download.html)
     - [Gobuster](https://github.com/OJ/gobuster/releases)
     - [FFuf](https://github.com/ffuf/ffuf/releases)
   - Add `C:\SecurityTools` to System PATH

## 📦 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/cybersec-agent.git
   cd cybersec-agent
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   source venv/bin/activate  # On Unix/macOS
   ```

3. **Install Dependencies**
   ```bash
   pip install -e .
   ```

