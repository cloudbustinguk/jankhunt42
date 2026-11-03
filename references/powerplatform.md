# Power Platform

Most enterprise citizen developers build in Microsoft Power Platform: Power Automate flows, Power Apps and Copilot
Studio agents. `scan` reads Power Automate cloud flows from the files makers export and commit, and reports four
risks that are common in citizen-built flows, plus any hardcoded secret.

jankhunt42 only reads the export. It never runs a flow, evaluates an expression, resolves a connection, signs in, or
fetches anything. A finding describes the configuration in the file; it cannot show which environment imported it,
whose account a connection uses, the tenant's data policy, or whether the flow is turned on.

## Which files are read

- **A solution export** (`.zip` with `solution.xml`, `customizations.xml` and `Workflows/<flow>.json`), managed or
  unmanaged.
- **A flow package** (Export > Package (.zip)): `manifest.json` with `Microsoft.Flow/flows/<id>/definition.json`.
- **The same files unpacked** and committed, for example by `pac solution unpack` (`Workflows/*.json`) or from a
  package's `Microsoft.Flow/flows/` folder.
- Any JSON whose `properties.definition` (or `definition`) is a workflow definition with `triggers` or `actions`.

A flow inside a zip is reported as `<zip path>!/<member>`, for example
`solutions/Contoso.zip!/Workflows/Notify-1A2B.json`. Every rule reads it as it would read the unpacked file, so a
literal password in an HTTP action is a `JH101` finding either way.

Zips are opened within fixed limits: 32 MB per zip, 5,000 entries, 4 MB per flow, 48 MB read per zip, and a
compression ratio of at most 200. Encrypted, oversized or over-compressed members, and zips whose entry names are
not valid UTF-8, are not read and are listed as warnings in every report format (JSON `warnings`, a "Not read" note
in Markdown, HTML and the terminal, and a SARIF tool execution notification). A zip that is not a Power Platform export is ignored. Only the manifest and the flows are read, never
other members.

## Rules

| Rule | Severity | What it reports | Not reported |
|---|---|---|---|
| JH144 | major (open to anyone); minor when not recorded | An HTTP request trigger open to **Anyone** (`All` or `Anyone`): whoever has the URL starts the flow, with no sign-in. When the export does not record who may call it, a minor lead to check the setting | Tenant or specific-user triggers; manual (Button), Power Apps and Copilot triggers, which sign the user in; schedules |
| JH145 | major (Key Vault); minor (HTTP) | Azure Key Vault **Get secret** without **Secure outputs**, or an HTTP action sending an `Authorization`/API-key header or an `authentication` block without **Secure inputs**. The value is then shown in the flow's run history | The same actions with Secure inputs/outputs turned on |
| JH146 | minor | A connector that can connect a personal account: Gmail, Outlook.com, OneDrive (personal), Dropbox, Google Drive, Sheets, Calendar, Contacts | Office 365 Outlook, OneDrive for Business, SharePoint and other organisation connectors |
| JH147 | major | Personal fields (email, phone, birth date, address, full name, national ID, passport; trigger fields and Dataverse columns such as `emailaddress1`, `birthdate`) sent to an AI service: AI Builder prompts (`aibuilderpredict_*`), AI connectors, or an HTTP call to an AI API | AI calls that send no personal field; a field read from a step named for redaction (`body('Redact_PII')?['email']`; also `Anonymise`, `Mask`); personal fields saved to Dataverse or sent to non-AI services |

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

Connector names follow Power Platform's API names (`/providers/Microsoft.PowerApps/apis/shared_<connector>`), read
from the action's `host` and the flow's `connectionReferences`.

## Not read yet

- Canvas apps (`.msapp`, `Src/*.pa.yaml`) beyond what `JH101` finds in unpacked formula files.
- Copilot Studio agents (topics, knowledge sources, the "No authentication" setting).
- Environment variable values, custom connectors, desktop flows, and `map`/`passport` reach for flows. n8n already
  has these in `map` (`references/n8n.md`).
- Solution zips in `review` (git) mode; `scan` reads them from the working tree.
