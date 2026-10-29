# ASP.NET Core and .NET builds

`scan` and `passport` read C# and MSBuild files without building or executing them.
The citizen passport includes exposed ASP.NET data endpoints and credentialed open
CORS among its public-exposure leads. `--ignore-rule` and the ordinary suppression
controls apply as documented in [rulesets](rulesets.md).

| Rule | Lead | Safe examples distinguished |
|---|---|---|
| JH135 | Application data returned or changed without visible authorization | Endpoint/group `RequireAuthorization`, controller/action `[Authorize]`, fallback authentication policy, constant health/metrics responses |
| JH136 | Any origin combined with credentials | Anonymous public CORS; exact trusted origins; separate policies |
| JH137 | Developer errors outside a development guard | Calls inside `if (Environment.IsDevelopment())`, including single statements |
| JH138 | Public cleartext Kestrel listener without visible redirection | Localhost, `UseHttps`, HTTPS redirection, development/launch settings |
| JH139 | Interpolated SQL reaching a string database API | Parameterized EF `FromSql`/`FromSqlInterpolated`, Dapper parameters, unused SQL examples |
| JH140 | Type metadata accepted during deserialization | `TypeNameHandling.None`, serialization-only settings, an explicit binder requiring separate review |
| JH141 | Personal fields passed to an identified AI client without visible redaction | Redacted fields, ordinary non-AI clients, string examples |
| JH142 | Floating PackageReference/PackageVersion | Fixed versions; XML comments |
| JH143 | Network download in an MSBuild Exec command | Local commands; XML comments |

Existing secret, certificate-validation and BinaryFormatter rules also apply.

These checks use masked code, balanced call/block spans and project-local context.
Simple boolean development checks and their branches are tracked; controls that
only run in development cannot stand for production controls. They do not resolve
C# symbols, evaluate MSBuild, prove data ownership, validate a
custom binder, or establish what a reverse proxy does. Authorization in custom
middleware, inherited/custom attributes, complex control flow, indirect SQL or AI
payload flows, and dynamically configured clients can be missed. JH135 focuses on
recognizable data routes and database writes; a POST which only acknowledges input
is not evidence of a persisted change. JH141 identifies known AI APIs/URLs and typed
HTTP clients registered with an AI address; an arbitrary external service is not
assumed to be AI. Application settings are scoped to the nearest visible project;
shared or generated startup configuration may need manual review.

For behavior during restore/build, opt in to [the sandbox](sandbox.md#net-and-nuget).
It acquires lock-pinned NuGet bytes separately, mounts the feed read-only and runs
restore/build offline in the .NET SDK image. Packages can execute MSBuild targets,
so a successful hash check establishes byte identity rather than trust. Without a
locked project, cache or SDK, the result describes the coverage gap.

The distinctions follow Microsoft's documentation on [authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple),
[CORS](https://learn.microsoft.com/en-us/aspnet/core/security/cors),
[development errors](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling),
[EF SQL parameters](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries),
[TypeNameHandling](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2326),
and [NuGet lock files](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies).
