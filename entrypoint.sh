#!/usr/bin/env bash

# If the environment is not set, set it to Production by default
if [ -z ${ASPNETCORE_ENVIRONMENT+x} ]; then
    ASPNETCORE_ENVIRONMENT="Production"
fi

set -e
set -u
set -o pipefail
set -x

# This is a workaround for dotnet6 outside of Visual Studio 
# packaging static files weird in Development mode.
# When restarting, the file may not exist anymore.
if [ "$ASPNETCORE_ENVIRONMENT" = "Development" ] && [ -f "VulnerabilityScannerTestApp.staticwebassets.runtime.json" ]; then
    rm VulnerabilityScannerTestApp.staticwebassets.runtime.json
fi

dotnet VulnerabilityScannerTestApp.dll