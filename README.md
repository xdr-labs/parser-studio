<h1 align="center">Parser Studio</h1>

<p align="center">
  <strong>Turn security logs into reviewed parser drafts—without starting with parser syntax.</strong>
</p>

<p align="center">
  Analyze representative events, check extracted fields, review Stellar Cyber normalization mappings, and download validated parser artifacts through a guided Web UI.
</p>

<p align="center">
  <strong>English</strong> · <a href="https://github.com/xdr-labs/parser-studio-docs">User Guide</a> · <a href="https://github.com/xdr-labs/parser-studio-docs/blob/main/scenarios/index.mdx">Scenario Playbooks</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Web-2563EB?style=flat-square" alt="Web">
  <img src="https://img.shields.io/badge/UI-React%20%2B%20TypeScript-7C3AED?style=flat-square" alt="React and TypeScript">
  <img src="https://img.shields.io/badge/workflows-Auto%20%2B%20ChatGPT-16A34A?style=flat-square" alt="Auto Parser and ChatGPT Assisted">
  <img src="https://img.shields.io/badge/output-Ruby%20%2B%20CONF-0891B2?style=flat-square" alt="Ruby and CONF drafts">
</p>

---

## What it does

Parser Studio is an independent, browser-based workspace for building custom security log parsers.

The guided workflow helps you:

- paste or upload representative security event samples
- identify supported record structures and inspect event boundaries
- review extracted fields, original values, and incomplete records
- assign and correct normalized field names using the available Stellar Cyber field catalog
- verify the complete sample instead of accepting partial matches
- create an integrity-checked **Ruby parser logic + CONF** draft pair, with optional package download
- compare browser-local working versions and investigate difficult cases using additional diagnostic tools
- download a standalone Python test sender that creates time-adjusted, synthetic variations of the sample

## Parser creation methods

Parser Studio provides **two** user-facing creation methods.

| Method | Best for | Workflow |
| --- | --- | --- |
| **Auto Parser** | Most new samples, including logs whose format you do not know | Add Logs → Review Fields → Map Fields → Create Parser |
| **ChatGPT Assisted Parser** | A record or mapping that still needs a carefully reviewed suggestion | Review and mask an example → copy a prompt manually → import a constrained JSON recipe → validate and approve |

Advanced diagnostics support these methods; they are not a separate creation workflow.

## Quick start

1. Open the Parser Studio Web UI and select **Auto Parser**.
2. Paste or upload a few complete records from the same source.
3. Choose **Analyze Logs**, then proceed through **Review Fields** and **Map Fields**.
4. Confirm that important values, record counts, and output mappings are correct.
5. Open **Create Parser** and select **Create Parser Files** when the sample passes the required checks.
6. Download the verified parser logic and companion configuration files.

To practice without customer data, follow the [first-parser walkthrough](https://github.com/xdr-labs/parser-studio-docs/blob/main/quickstart.mdx).

## Supported source review

Parser Studio includes format recognition and review paths for commonly encountered security log structures:

- JSON, including nested fields
- key/value (KV) records
- CEF and LEEF events
- Syslog envelopes and structured message bodies
- CSV with explicitly reviewed column names and delimiters
- bounded mixed-format and explicitly framed multiline cases

**Recognition is not the same as successful generation.** Actual draft support depends on the precise source structure, reviewed mappings, event boundaries, and connected compiler capabilities. Unsupported or ambiguous records remain visible for review.

## Generated files

When all required checks pass, the application can offer:

| Artifact | Purpose |
| --- | --- |
| **Ruby parser logic** (extensionless) | Parsing rules generated for the reviewed source |
| **CONF** | Companion parser configuration for the same draft |
| **Package archive** (when available) | A bundled copy of the generated artifacts |

Returned artifacts undergo SHA-256 integrity checks. Keep the two files from the same generation together. A successful download validates the reviewed draft and its checks; it does not guarantee correct behavior for unseen log variations.

## Privacy and review safeguards

- Standard source previews run in the browser; do not assume that private logs are safe to share merely because they appear in a sample.
- The ChatGPT-assisted method requires **manual review, redaction, copying, and pasting**. There is no automatic ChatGPT submission.
- Proposed changes are constrained to the supported structured recipe and may require independent holdout events before approval.
- The downloadable Python test sender contains the source sample in **base64, not encryption**. Mask sensitive content before distributing the file.
- Treat all output files as reviewed drafts and verify them against representative source records.

## Development

For contributors with access to the repository, start the local Web UI with Node.js and npm:

```bash
git clone https://github.com/xdr-labs/parser-studio.git
cd parser-studio
npm ci
npm run dev
```

The default development UI binds to `127.0.0.1`. Some generation and advanced analysis operations require a compatible local parser backend; starting the UI alone does not establish compiler availability.

Common checks:

```bash
npm test
npm run build
npm run test:browser
```

## Documentation

The maintained user manual is in **[Parser Studio Docs](https://github.com/xdr-labs/parser-studio-docs)**. Start with:

- [Create your first parser](https://github.com/xdr-labs/parser-studio-docs/blob/main/quickstart.mdx)
- [Choose a workflow](https://github.com/xdr-labs/parser-studio-docs/blob/main/choose-workflow.mdx)
- [Auto Parser guide](https://github.com/xdr-labs/parser-studio-docs/blob/main/workflows/auto-parser.mdx)
- [ChatGPT Assisted Parser guide](https://github.com/xdr-labs/parser-studio-docs/blob/main/workflows/chatgpt-assisted.mdx)
- [Scenario playbooks](https://github.com/xdr-labs/parser-studio-docs/blob/main/scenarios/index.mdx)
- [Troubleshooting](https://github.com/xdr-labs/parser-studio-docs/blob/main/reference/troubleshooting.mdx)

Technical design and ongoing engineering decisions are maintained separately in this product repository.

## Related projects

- [Parser Studio Docs](https://github.com/xdr-labs/parser-studio-docs) — user manual and scenario playbooks
- [XDR Labs Portal](https://xdr.ooo/) — XDR Labs project portal

---

<p align="center">
  <strong>Add logs. Review fields. Map accurately. Create with confidence.</strong>
</p>
