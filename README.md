# 🐍 Dark Basilisk

Command-line cybersecurity agent that runs an agent loop powered by Anthropic's Claude with a comprehensive set of tools for both red and blue team operations. It's designed to be a versatile and autonomous assistant for cybersecurity professionals, capable of performing a wide range of tasks from reconnaissance to incident response.

# ✨ Main Features

- **Red Team: ⚔️** DNS/subdomain enumeration, HTTP path probing, TLS inspection, web fingerprinting, SQLi/XSS/SSRF/open-redirect probes, IDOR and credential-spray tests, virtual-host discovery, GraphQL introspection, .git/.env/backup artifact checks, cloud-storage exposure checks.
- **Blue Team: 🛡️** Sigma rule generation, log triage, dependency audit, security-header hardening, IOC classification and blocklist checks.

# ✅ Prerequisites

- **Bun**, the fast JS runtime and package manager.
- **Anthropic API key**, available at [official platform](https://platform.claude.com/).

# ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/germanocastanho/dark-basilisk
cd dark-basilisk/

# Install dependencies
bun install
bun link

# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Run the agent
basilisk
```

# 📜 Libre Software

If you have ideas for improvements or new features, please open an issue or submit a pull request. Make sure to follow the existing code style and include tests for any new functionality. Licensed under the GNU GPL v3, so you are free to use, modify, and distribute this software. Please refer to the [LICENSE](LICENSE) for more!
