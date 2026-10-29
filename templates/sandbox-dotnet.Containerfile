# SDK runner for .NET repositories. Build once from this trusted template, never from a repository under test.
FROM mcr.microsoft.com/dotnet/sdk:10.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace python3 python3-pip python3-venv ca-certificates curl wget nodejs npm \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 runner
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NUGET_XMLDOC_MODE=skip
USER 10001
WORKDIR /work
