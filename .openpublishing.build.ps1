param(
    [string]$buildCorePowershellUrl = "https://opbuildstoragesandbox2.blob.core.windows.net/opps1container/.openpublishing.buildcore.ps1",
    [string]$parameters
)
# Main
$errorActionPreference = 'Stop'

# Step-1 Download buildcore script to local
echo "download build core script to local with source url: $buildCorePowershellUrl"
$repositoryRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$buildCorePowershellDestination = "$repositoryRoot\.openpublishing.buildcore.ps1"
Invoke-WebRequest $buildCorePowershellUrl -OutFile $buildCorePowershellDestination

# Step-2: Run build core
echo "run build core script with parameters: $parameters"
$arguments = "-parameters:'$parameters;_op_accessToken=7843e25561a5d98a7b494294facf641f5f1ea88d'"
Invoke-Expression "$buildCorePowershellDestination $arguments"
exit $LASTEXITCODE