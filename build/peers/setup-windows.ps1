<#
.SYNOPSIS
    The ACME peers of the Windows leg - Posh-ACME and win-acme - installed for
    the current user, at their pins (pins.env).

.DESCRIPTION
    No WSL in it: the clients run as the Windows programs they are, against a
    server of the test process on the loopback, where no firewall stands
    between them. Nothing is installed system-wide and nothing is registered:
    both go into a directory of their own (PKICONFORMANCE_WINDOWS_LIB, or
    %LOCALAPPDATA%\pkiconformance by default), each download checked against
    the hash its publisher publishes before it is unpacked. The suite finds
    them there (Peers/PoshACME.cs, Peers/WinAcme.cs).

    Runs in Windows PowerShell 5.1 and in PowerShell 7.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build\peers\setup-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build\peers\setup-windows.ps1 -Check
#>
param(
    # Only say what is there.
    [switch] $Check
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pins = @{}

foreach ($line in Get-Content (Join-Path $here 'pins.env')) {
    if ($line -match '^\s*([A-Z0-9_]+)=(.*)$') {
        $pins[$Matches[1]] = $Matches[2].Trim()
    }
}

$lib = $env:PKICONFORMANCE_WINDOWS_LIB
if (-not $lib) {
    $lib = Join-Path $env:LOCALAPPDATA 'pkiconformance'
}

$poshDir = Join-Path $lib ('Posh-ACME-' + $pins['POSHACME_VERSION'])
$wacsDir = Join-Path $lib ('win-acme-'  + $pins['WINACME_VERSION'])


# What is there, said on the host - the function's output is its verdict alone.
function Test-Installed {

    $posh = Test-Path (Join-Path $poshDir 'Posh-ACME.psd1')
    $wacs = Test-Path (Join-Path $wacsDir 'wacs.exe')

    Write-Host ('Posh-ACME ' + $pins['POSHACME_VERSION'] + ': ' + $(if ($posh) { $poshDir } else { 'missing' }))
    Write-Host ('win-acme '  + $pins['WINACME_VERSION']  + ': ' + $(if ($wacs) { $wacsDir } else { 'missing' }))

    return ($posh -and $wacs)

}

# The hash of a file, hexadecimal in lower case.
function Get-Hash([string] $Path, [string] $Algorithm) {
    return (Get-FileHash -Path $Path -Algorithm $Algorithm).Hash.ToLowerInvariant()
}

# A download into a file, or the script's end.
function Get-Download([string] $Uri, [string] $OutFile) {
    Write-Host "  $Uri"
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile
}


if ($Check) {
    if (Test-Installed) { exit 0 } else { exit 1 }
}

# Windows PowerShell 5.1 speaks TLS 1.0 by default, which the gallery and
# GitHub refuse.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force -Path $lib | Out-Null

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('pkiconformance-setup-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

try {

    if (-not (Test-Path (Join-Path $poshDir 'Posh-ACME.psd1'))) {

        Write-Host ('Posh-ACME ' + $pins['POSHACME_VERSION'] + ', from the PowerShell Gallery:')

        # A .nupkg is a zip; Expand-Archive of 5.1 takes .zip alone.
        $package = Join-Path $scratch 'posh-acme.zip'
        Get-Download ('https://www.powershellgallery.com/api/v2/package/Posh-ACME/' + $pins['POSHACME_VERSION']) $package

        $expected = -join ([Convert]::FromBase64String($pins['POSHACME_SHA512']) | ForEach-Object { $_.ToString('x2') })
        $actual   = Get-Hash $package 'SHA512'

        if ($actual -ne $expected) {
            throw "Posh-ACME: SHA-512 $actual, the gallery publishes $expected - not unpacked."
        }

        $unpacked = Join-Path $scratch 'posh-acme'
        Expand-Archive -Path $package -DestinationPath $unpacked -Force

        # What NuGet adds around the module.
        foreach ($nuget in @('[Content_Types].xml', '_rels', 'package', 'Posh-ACME.nuspec')) {
            Remove-Item -LiteralPath (Join-Path $unpacked $nuget) -Recurse -Force -ErrorAction SilentlyContinue
        }

        Move-Item -Path $unpacked -Destination $poshDir

    }

    if (-not (Test-Path (Join-Path $wacsDir 'wacs.exe'))) {

        Write-Host ('win-acme ' + $pins['WINACME_VERSION'] + ', from GitHub:')

        $zip = Join-Path $scratch 'win-acme.zip'
        Get-Download ('https://github.com/win-acme/win-acme/releases/download/' + $pins['WINACME_TAG'] + '/win-acme.v' + $pins['WINACME_VERSION'] + '.x64.pluggable.zip') $zip

        $actual = Get-Hash $zip 'SHA256'

        if ($actual -ne $pins['WINACME_SHA256']) {
            throw ('win-acme: SHA-256 ' + $actual + ', GitHub publishes ' + $pins['WINACME_SHA256'] + ' - not unpacked.')
        }

        Expand-Archive -Path $zip -DestinationPath $wacsDir -Force

    }

}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Installed)) {
    exit 1
}
