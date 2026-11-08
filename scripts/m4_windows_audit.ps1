# Windows MSVC candidate audit. Run from a VS Developer PowerShell shell.
# Requires /MT for all first-party/third-party code; fail if VC runtime or
# non-OS third-party DLLs are imported. This does not prove Windows 10 support.
param(
    [Parameter(Mandatory=$true)][string]$Stage,
    [Parameter(Mandatory=$true)][string]$VcpkgRoot
)
$ErrorActionPreference = 'Stop'
$Stage = (Resolve-Path $Stage).Path
$VcpkgRoot = (Resolve-Path $VcpkgRoot).Path
# PowerShell jobs may have MSVC installed without a Developer PowerShell PATH.
$tool = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
$dumpbin = if ($tool) { $tool.Source } else { $null }
if (-not $dumpbin) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'MSVC dumpbin not on PATH and vswhere unavailable' }
    $vs = (& $vswhere -latest -products '*' -property installationPath | Select-Object -First 1)
    if (-not $vs) { throw 'Visual Studio MSVC toolchain installation not found' }
    $msvc = Get-ChildItem (Join-Path $vs 'VC/Tools/MSVC') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    $dumpbin = Join-Path $msvc.FullName 'bin/Hostx64/x64/dumpbin.exe'
    if (-not (Test-Path $dumpbin)) { throw "dumpbin unavailable at $dumpbin" }
}
$osLibraries = @(
    'KERNEL32.DLL', 'USER32.DLL', 'GDI32.DLL', 'OPENGL32.DLL',
    'WS2_32.DLL', 'IPHLPAPI.DLL', 'ADVAPI32.DLL', 'CRYPT32.DLL',
    'BCRYPT.DLL', 'SHELL32.DLL', 'OLE32.DLL', 'OLEAUT32.DLL',
    'SHLWAPI.DLL', 'NTDLL.DLL', 'WINMM.DLL', 'SETUPAPI.DLL',
    'IMM32.DLL', 'COMDLG32.DLL', 'VERSION.DLL', 'RPCRT4.DLL',
    'WINHTTP.DLL', 'SECUR32.DLL', 'DWMAPI.DLL', 'UXTHEME.DLL',
    'WIN32U.DLL', 'DXGI.DLL', 'D3D11.DLL', 'NORMALIZ.DLL',
    'WLDAP32.DLL', 'USERENV.DLL', 'SHELL32.DLL', 'CFGMR32.DLL',
    'DNSAPI.DLL', 'PSAPI.DLL'
)
$inventory = @{}
foreach ($name in @('xorcist.exe','xorcist-gui.exe')) {
    $path = Join-Path $Stage "bin/$name"
    if (-not (Test-Path $path)) { throw "Missing executable: $path" }
    $dump = & $dumpbin /DEPENDENTS $path
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed for $path" }
    $dlls = @($dump | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z0-9_.-]+\.dll)\s*$') { $Matches[1].ToUpperInvariant() }
    } | Sort-Object -Unique)
    if ($dlls.Count -eq 0) { throw "No imports detected for $name; dumpbin parsing may be broken" }
    foreach ($dll in $dlls) {
        if ($dll -like 'API-MS-WIN-*' -or $dll -like 'EXT-MS-WIN-*') { continue }
        if ($dll -notin $osLibraries) {
            throw "Unexpected imported DLL in ${name}: $dll. Review and explicitly package/audit or switch to static linking."
        }
    }
    $inventory[$name] = @{
        sha256 = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
        imported_dlls = @($dlls)
    }
}
$copyright = Join-Path $VcpkgRoot 'installed/x64-windows-static/share/openssl/copyright'
if (-not (Test-Path $copyright)) { throw "Missing exact installed OpenSSL notice: $copyright" }
$dest = Join-Path $Stage 'share/doc/xorcist/third-party-licenses/OPENSSL_VCPKG_COPYRIGHT.txt'
Copy-Item $copyright $dest -Force
$report = @{
    schema = 'xorcist.m4.windows-imports.v1'
    triplet = 'x64-windows-static'
    note = 'Only expected OS DLL imports observed; test physical Windows 10/11 before release.'
    executables = $inventory
}
$report | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $Stage 'share/doc/xorcist/WINDOWS_IMPORTS.json') -Encoding utf8
Write-Host 'PASS: Windows static-link import audit; OpenSSL copyright copied.'
