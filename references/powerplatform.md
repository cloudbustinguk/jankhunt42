# Power Platform

Most enterprise citizen developers build in Microsoft Power Platform: Power Automate flows, Power Apps and Copilot
Studio agents. `scan` reads the files makers export and commit: cloud flows, canvas apps, Copilot Studio agents and
environment variables. It reports six risks that are common in citizen-built solutions, plus any hardcoded secret,
including one in a canvas app's formulas.

jankhunt42 only reads the export. It never runs a flow or an app, evaluates an expression, resolves a connection,
signs in, or fetches anything. A finding describes the configuration in the file; it cannot show which environment imported it,
whose account a connection uses, the tenant's data policy, or whether the flow is turned on.

## Which files are read

- **A solution export** (`.zip` with `solution.xml`, `customizations.xml` and `Workflows/<flow>.json`), managed or
  unmanaged.
- **A flow package** (Export > Package (.zip)): `manifest.json` with `Microsoft.Flow/flows/<id>/definition.json`.
- **The same files unpacked** and committed, for example by `pac solution unpack` (`Workflows/*.json`) or from a
  package's `Microsoft.Flow/flows/` folder.
- Any JSON whose `properties.definition` (or `definition`) is a workflow definition with `triggers` or `actions`.
- **Canvas apps:** an `.msapp` committed on its own, or `CanvasApps/<name>.msapp` inside a solution zip (opened one
  level deep, never further). An `.msapp` is itself a zip. Its Power Fx source, `Src/*.pa.yaml`, is read as written.
  An app saved before that format exists keeps its formulas in `Controls/*.json` and `Components/*.json`; those are
  read as a listing, one line per property (`Screen1.OnVisible: =Set(gblApiKey, "...")`), reported as
  `<member>!/formulas.yaml`.
- **Copilot Studio agents:** `bots/<schema>/bot.xml` and `configuration.json`, and the agent's components,
  `botcomponents/<schema>/data` (topics, tools and instructions, in YAML), zipped or unpacked. An agent cloned with
  the Copilot Studio extension for VS Code is read too: `settings.mcs.yml`, `agent.mcs.yml`, and the `*.mcs.yml`
  files in `topics/` and `actions/`.
- **Environment variables:** `environmentvariabledefinitions/<schema>/environmentvariabledefinition.xml` (type and
  default value) and `environmentvariablevalues.json` beside it (the current value, when the solution was exported
  with values), zipped or unpacked.

A flow inside a zip is reported as `<zip path>!/<member>`, for example
`solutions/Contoso.zip!/Workflows/Notify-1A2B.json`, and a canvas app's screen inside it as
`solutions/Contoso.zip!/CanvasApps/contoso_app_DocumentUri.msapp!/Src/Screen1.pa.yaml`. Every rule reads a member as it
would read the unpacked file, so a literal password in an HTTP action or a `Set(gblApiKey, "...")` formula is a `JH101`
finding either way. So is an API key typed into a topic's HTTP request header, plain or as a Power Fx text
(`x-api-key: ="..."`); a header read from an environment variable or a variable is not.

Zips are opened within fixed limits: 32 MB per zip, 5,000 entries, 4 MB per member read (16 MB for a canvas app's
screen), 16 MB per canvas app and 32 apps per solution, 48 MB read per zip (a canvas app and its members count toward the zip around it), and a compression
ratio of at most 200. Encrypted, oversized or over-compressed members, apps that are not readable zips, and zips
whose entry names are not valid UTF-8, are not read and are listed as warnings in every report format (JSON
`warnings`, a "Not read" note in Markdown, HTML and the terminal, and a SARIF tool execution notification). A zip
that is not a Power Platform export or canvas app is ignored. Only the members listed above are read, never others
(knowledge files, images, connectors).

## Rules

| Rule | Severity | What it reports | Not reported |
|---|---|---|---|
| JH144 | major (open to anyone); minor when not recorded | An HTTP request trigger open to **Anyone** (`All` or `Anyone`): whoever has the URL starts the flow, with no sign-in. When the export does not record who may call it, a minor lead to check the setting | Tenant or specific-user triggers; manual (Button), Power Apps and Copilot triggers, which sign the user in; schedules |
| JH145 | major (Key Vault); minor (HTTP) | Azure Key Vault **Get secret** without **Secure outputs**, or an HTTP action sending an `Authorization`/API-key header or an `authentication` block without **Secure inputs**. The value is then shown in the flow's run history | The same actions with Secure inputs/outputs turned on |
| JH146 | minor | A connector that can connect a personal account: Gmail, Outlook.com, OneDrive (personal), Dropbox, Google Drive, Sheets, Calendar, Contacts | Office 365 Outlook, OneDrive for Business, SharePoint and other organisation connectors |
| JH147 | major | Personal fields (email, phone, birth date, address, full name, national ID, passport; trigger fields and Dataverse columns such as `emailaddress1`, `birthdate`) sent to an AI service: AI Builder prompts (`aibuilderpredict_*`), AI connectors, or an HTTP call to an AI API | AI calls that send no personal field; a field read from a step named for redaction (`body('Redact_PII')?['email']`; also `Anonymise`, `Mask`); personal fields saved to Dataverse or sent to non-AI services |
| JH148 | major | A Copilot Studio agent set to **No authentication** (`authenticationmode` 1): anyone who can reach it, on a website, the demo page or another channel, chats with it without signing in, and the connector actions it calls run with the maker's connections | Agents set to Authenticate with Microsoft (2), manual sign-in (3, 4), or unspecified (0) |
| JH149 | major; critical when the value is in the export | An environment variable named for a secret (API key, client secret, password, token, connection string, in its schema or display name) whose type is **Text**, not **Secret**: its value is stored and exported in plain text. Critical when the export carries a default or current value that could be the secret; the value is never shown | Secret-type variables (Azure Key Vault references), other types, placeholders (`<...>`, `changeme`, `Enter ...`), URLs, and values with spaces |
| JH150 | major; critical when the agent needs no sign-in | A Copilot Studio tool (connector, flow, MCP server) or a topic's connector step set to **Maker-provided credentials** (`connectionProperties: mode: Maker`): everyone who chats with the agent acts with the maker's own access. Critical when the agent also needs no sign-in (JH148) | Tools on the user's own credentials (`mode: Invoker`) |
| JH151 | major (plain HTTP, other port); minor (around a connector) | A topic's **HTTP request** to a plain `http://` URL or a port other than 443, or to a Microsoft service that has a connector (Graph, SharePoint, Dynamics, Outlook, Azure management, Power BI, Key Vault), where the connector's data policies do not apply | HTTPS on 443; `localhost`; URLs built from environment variables or variables, which the export does not resolve |
| JH152 | minor | An agent with **generative orchestration** on (`GenerativeActionsEnabled`) and no **instructions**: the model chooses topics, tools and answers with nothing stating the agent's purpose, scope or limits | Agents with instructions; classic agents; an export without the agent's configuration |
| JH153 | major | An email tool (Office 365 Outlook, Outlook.com, Gmail: send, send from a shared mailbox, forward, approval mail) whose recipient the **AI fills in**: injected instructions can make the agent mail conversation data to any address | A recipient set as a fixed input (`ManualTaskInput`, including the signed-in user's address); replies and drafts |

How sure each rule is:
- **JH144:** Microsoft documents the "Who can trigger the flow" options, not how an export writes them. Public flow
  definitions write `triggerAuthenticationType` under the trigger's `inputs`, with `All` for the open mode; `Anyone`
  (the designer's label) is read too. Any other value is taken as a sign-in mode. A flow made before sign-in options existed records nothing and accepts anyone with the URL, which is
  why an unrecorded setting is still a lead.
- **JH145:** who can open a flow's run history is not in the export. Secure inputs/outputs only hide values in run
  history. They are not encryption, and they do not stop a
  later action from using or exposing the value.
- **JH146:** a connector that *can* use a personal account. Gmail also serves Google Workspace accounts. Whether this
  connection is personal, and how your data policy classifies the connector, is not in the export.
- **JH147:** field names are a heuristic, and this is not data-flow analysis. A field passed through an expression the
  reader cannot follow is not reported. A field read from a step named for redaction is trusted by that step's name;
  the word in a prompt ("do not redact") is not a redaction.
- **JH148:** `authenticationmode` is the Dataverse bot table's choice: 0 Unspecified, 1 None, 2 Integrated
  (Authenticate with Microsoft), 3 Custom Entra ID, 4 Generic OAuth2. Some agents are meant to be public: a website
  FAQ with no actions and only public knowledge is fine. The finding is a prompt to confirm that, because the export
  does not say which channels are published. An agent cloned with VS Code writes the same choice as
  `authenticationMode: None` in `settings.mcs.yml`.
- **JH149:** Microsoft's documentation warns that a secret kept in a Text variable is not encrypted. Names are a
  heuristic. A current value is reported under a credential name, and under a name that only ends in `key`
  (`DemoKey`) when the value is long and mixes letters and digits, never a GUID.
- **JH150 to JH153** follow Microsoft's list of the Copilot Studio misconfigurations it finds most
  ([Detecting and mitigating common agent misconfigurations](https://www.microsoft.com/en-us/security/blog/2026/02/12/copilot-studio-agent-security-top-10-risks-detect-prevent/),
  February 2026), and read the YAML that Microsoft's own samples and the VS Code extension write.
  - **JH150:** `mode: Maker` is Microsoft's Maker-provided credentials, and it is explicit in the export. Whether the
    maker's connection has wide access is not in the export.
  - **JH151:** only a URL written as text, or a Power Fx text it starts with (`="http://host/" & Topic.Id`), is read.
  - **JH152:** whether the agent is published is not in the export.
  - **JH153:** what counts as an email tool comes from Microsoft's connector reference. A tool that sends only to the
    signed-in user is not reported, because its recipient is a fixed input.

Connector names follow Power Platform's API names (`/providers/Microsoft.PowerApps/apis/shared_<connector>`), read
from the action's `host` and the flow's `connectionReferences`.

## Not read yet

- Copilot Studio knowledge sources, agent channels and sharing, and which tools a topic hands to a child agent.
  Sharing, usage and owners are tenant state, not in an export.
- A canvas app's data sources and connections, custom connectors, desktop flows, and `map`/`passport` reach for
  flows, apps and agents. n8n already has these in `map` (`references/n8n.md`).
- Solution zips in `review` (git) mode; `scan` reads them from the working tree.
