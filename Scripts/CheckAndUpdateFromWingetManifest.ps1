Param(
    [string]$WingetIdsFile   = ".\winget_ids.txt",        
    [string]$GitHubToken     = ${env:PAT_TOKEN},           # GitHub personal access token
    [string]$KomacPath       = "C:\Program Files\Komac\bin\Komac.exe",
    [string]$LastCheckedFile = ".\last_checked.json",     # store Winget IDs + last-check times
    [int]$SkipHours          = 24                         # skip re-check for 24 hours
)

##############################################################################
# 0. Load or Initialize "last-checked" hashtable
##############################################################################
[Hashtable]$lastCheckedMap = @{}
if (Test-Path $LastCheckedFile) {
    try {
        $jsonContent = Get-Content $LastCheckedFile -Raw
        $tempObj     = $jsonContent | ConvertFrom-Json
        if ($tempObj) {
            foreach ($prop in $tempObj.PSObject.Properties) {
                $lastCheckedMap[$prop.Name] = $prop.Value
            }
        }
    }
    catch {
        Write-Warning "Failed to load $LastCheckedFile $_"
    }
}

##############################################################################
# 1. Ensure required modules and files exist
##############################################################################
if (-not (Test-Path $WingetIdsFile)) {
    Write-Error "Winget IDs file '$WingetIdsFile' not found."
    exit 1
}

# Ensure Winget module is available (e.g., PSWinget or equivalent)
if (-not (Get-Module -ListAvailable -Name PSWinget) -and -not (Get-Command Find-WinGetPackage -ErrorAction SilentlyContinue)) {
    Write-Error "Please install a Winget PowerShell module that provides Find-WinGetPackage."
    exit 1
}

# Ensure powershell-yaml is installed
if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    try {
        Install-Module -Name powershell-yaml -Scope CurrentUser -Force
    }
    catch {
        Write-Error "Could not install powershell-yaml. Please install manually. Exiting."
        exit 1
    }
}
Import-Module powershell-yaml -ErrorAction Stop

# Read all Winget IDs
$wingetIds = Get-Content $WingetIdsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if ($wingetIds.Count -eq 0) {
    Write-Host "No Winget IDs found in '$WingetIdsFile'. Exiting."
    exit 0
}
Write-Host "=== Found $($wingetIds.Count) Winget IDs to check ==="

##############################################################################
# 2. Save-LastChecked helper function
##############################################################################
function Save-LastChecked {
    param(
        [Hashtable]$Map,
        [string]$Path
    )
    $psObj = New-Object PSObject
    foreach ($key in $Map.Keys) {
        $psObj | Add-Member -MemberType NoteProperty -Name $key -Value $Map[$key]
    }
    try {
        $psObj | ConvertTo-Json -Depth 5 | Out-File $Path -Force -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write $Path $_"
    }
}

##############################################################################
# 3. Helper Functions
##############################################################################

function Get-CurrentWingetVersion {
    param(
        [Parameter(Mandatory)] [string]$WingetID
    )
    try {
        $pkg = Find-WinGetPackage -ID $WingetID -Source winget | Select-Object -First 1
        if ($pkg) { return $pkg.Version }
        else       { return $null }
    }
    catch {
        Write-Warning "Failed to run Find-WinGetPackage for $WingetID $_"
        return $null
    }
}

function Get-InstallerManifestFromWingetPkgs {
    param(
        [Parameter(Mandatory)] [string]$PackageId,
        [string]$GitHubToken
    )
    $searchString = "PackageIdentifier: $PackageId ManifestType: installer"
    $encoded      = [System.Web.HttpUtility]::UrlEncode($searchString)
    $searchUrl    = "https://api.github.com/search/code?q=$encoded+in:file+repo:microsoft/winget-pkgs"

    $headers = @{ "User-Agent" = "WingetManifestCheck" }
    if ($GitHubToken) { $headers["Authorization"] = "Bearer $GitHubToken" }

    try {
        $resp = Invoke-RestMethod -Uri $searchUrl -Headers $headers -Method GET
        Start-Sleep -Seconds 1
        if ($resp.total_count -eq 0) { return $null }
        $sorted = $resp.items |
            ForEach-Object {
                $v = Get-VersionFromPath $_.path
                if ($v) {
                    [PSCustomObject]@{
                        item    = $_
                        version = $v
                    }
                }
            } | Sort-Object -Property version -Descending
        if ($sorted.Count -eq 0) { return $null }
        $bestMatch = $sorted[0].item
        $rawUrl = $bestMatch.html_url -replace "github.com/microsoft/winget-pkgs/blob", "raw.githubusercontent.com/microsoft/winget-pkgs"
        Write-Host "Found manifest file at $($bestMatch.path)"
        Write-Host "Raw URL => $rawUrl"
        return Invoke-RestMethod -Uri $rawUrl -Headers $headers -Method GET
    }
    catch {
        Write-Warning "Failed searching for $PackageId $($_.Exception.Message)"
        return $null
    }
}

function Get-VersionFromPath {
    param([string]$Path)
    if (-not $Path) { return $null }
    $split = $Path -split '/'
    if ($split.Count -lt 2) { return $null }
    $verString = $split[$split.Count - 2]
    try {
        return [version]$verString
    }
    catch {
        return $null
    }
}

function ParseOwnerRepoFromGitHubUrl {
    param([string]$Url)
    if ($Url -notmatch 'https://github.com/([^/]+)/([^/]+)/releases/download') {
        return $null
    }
    return "$($matches[1])/$($matches[2])"
}

function Get-GitHubLatestRelease {
    param(
        [Parameter(Mandatory)] [string]$OwnerRepo,
        [string]$GitHubToken
    )
    $url = "https://api.github.com/repos/$OwnerRepo/releases/latest"
    $headers = @{ "User-Agent" = "WingetManifestCheck" }
    if ($GitHubToken) { $headers["Authorization"] = "Bearer $GitHubToken" }
    try {
        return Invoke-RestMethod -Uri $url -Headers $headers -Method GET
    }
    catch {
        Write-Warning "Failed to retrieve latest release for $OwnerRepo $($_.Exception.Message)"
        return $null
    }
}

function Convert-ToVersionOrNull {
    param([Parameter(Mandatory)][string]$TagName)
    $raw = $TagName.TrimStart('v')
    try {
        return [version]$raw
    }
    catch {
        $clean = $raw -replace '^([\d\.]+).*', '$1'
        if (-not $clean) { return $null }
        try { return [version]$clean }
        catch { return $null }
    }
}

# New function to check for an open PR for a given package.
function Get-ExistingPRs {
    param(
        [Parameter(Mandatory)][string]$PackageId,
        [string]$GitHubToken
    )
    # List up to 100 open PRs in the winget-pkgs repo
    $prUrl = "https://api.github.com/repos/microsoft/winget-pkgs/pulls?state=open&per_page=100"
    $headers = @{
        "User-Agent" = "WingetManifestCheckScript"
    }
    if ($GitHubToken) {
        $headers["Authorization"] = "token " + $GitHubToken
    }
    try {
        $prs = Invoke-RestMethod -Uri $prUrl -Headers $headers -Method GET
        Start-Sleep -Seconds 1
        # Build a regex pattern that matches titles like:
        # "Update version: <PackageId> version <something>" or
        # "New version: <PackageId> version <something>"
        $pattern = "^(Update|New) version:\s*" + [Regex]::Escape($PackageId) + "\s+version\s+\S+"
        foreach ($pr in $prs) {
            if ($pr.title -match $pattern) {
                Write-Host "Found open PR with title $($pr.title) matching pattern $pattern"
                return $true
            }
        }
        return $false
    }
    catch {
        Write-Warning ("Failed to list PRs for package " + $PackageId + " " + $_.Exception.Message)
        return $false
    }
}

function Find-NewAssetUrlHybrid {
    param(
        [Parameter(Mandatory)] $oldInstaller,          # Old installer object from the previous manifest.
        [Parameter(Mandatory)] [Version]$newVersion,    # New version (as a [Version] object).
        [Parameter(Mandatory)] $assets                 # Array of new release assets from GitHub.
    )
    # Get basic file details from the old installer.
    $oldUrl = $oldInstaller.InstallerUrl
    $oldFileName = [System.IO.Path]::GetFileName($oldUrl)
    $oldExt = [System.IO.Path]::GetExtension($oldFileName).ToLowerInvariant()

    # Extract old version from the InstallerVersion property if available; otherwise, try to parse from filename.
    $oldInstallerVersion = $oldInstaller.InstallerVersion
    if (-not $oldInstallerVersion) {
        if ($oldFileName -match '_v?((\d+\.)+\d+)') {
            $oldInstallerVersion = $matches[1]
        }
        else {
            # Fallback: extract first occurrence of a digit sequence with dots.
            if ($oldFileName -match '((\d+\.)+\d+)') {
                $oldInstallerVersion = $matches[1]
            }
        }
    }
    if (-not $oldInstallerVersion) {
        Write-Warning "Could not determine old version from $oldFileName"
        return $null
    }
    $oldVerString = $oldInstallerVersion
    $newVerString = $newVersion.ToString()

    # Direct substitution: form a candidate filename by replacing the old version with the new version.
    Write-Host "Trying direct substitution for $oldFileName"
    $candidateName = $oldFileName -replace [Regex]::Escape($oldVerString), $newVerString
    Write-Host "Candidate new name: $candidateName"
    foreach ($asset in $assets) {
        if ($asset.name -eq $candidateName) {
            Write-Host "Exact filename match found: $($asset.name)"
            return $asset.browser_download_url
        }
    }

    Write-Host "No exact match found. Falling back to pattern-based matching..."
    # Determine the desired architecture from the old manifest.
    $desiredArch = $oldInstaller.Architecture.ToLowerInvariant()
    $oldFileNameLower = $oldFileName.ToLowerInvariant()
    # Normalize architecture based on filename hints.
    if ($oldFileNameLower -match 'x86_64|amd64|\bx64\b') {
        $desiredArch = "x64"
    }
    elseif ($oldFileNameLower -match 'i386|x86|\b32\b') {
        $desiredArch = "x86"
    }
    
    foreach ($asset in $assets) {
        $assetName = $asset.name
        $assetExt = [System.IO.Path]::GetExtension($assetName).ToLowerInvariant()
        if ($assetExt -ne $oldExt) { continue }
        # Ensure the asset name contains the new version string.
        if ($assetName -notmatch [Regex]::Escape($newVerString)) { continue }
        
        # Check for architecture markers:
        $assetNameLower = $assetName.ToLowerInvariant()
        switch ($desiredArch) {
            'x64' {
                # For x64, ensure that asset name has an accepted marker and does NOT include "arm64"
                if ($assetNameLower -match '(?i)arm64') { continue }
                if (-not ($assetNameLower -match '(?i)(x86_64|amd64|\bx64\b)')) { continue }
            }
            'x86' {
                if (-not ($assetNameLower -match '(?i)(x86|32|386)')) { continue }
            }
            'arm64' {
                if (-not ($assetNameLower -match '(?i)arm64')) { continue }
            }
            default {
                # For unknown architectures, we don’t enforce extra checks.
            }
        }
        Write-Host "Fallback match found: $assetName"
        return $asset.browser_download_url
    }
    Write-Warning "No suitable asset found for $oldFileName"
    return $null
}



##############################################################################
# 4. Komac Logic: Fix manifests, then submit PR
##############################################################################
function Fix-KomacManifestsAndSubmit {
    param(
        [Parameter(Mandatory)] [string]$KomacPath,
        [Parameter(Mandatory)] [string]$WingetId,
        [Parameter(Mandatory)] [version]$NewVersion,
        [Parameter(Mandatory)] [string[]]$InstallerUrls,
        [Parameter(Mandatory)] $OldInstallers,  # Array of installer objects from the old manifest.
        [string]$OutputFolder = ".komac/$WingetId",
        [string]$GitHubToken,
        [switch]$OpenPr
    )
    # Update token if provided.
    if ($GitHubToken) {
        & $KomacPath token update --token $GitHubToken
    }
    # STEP 1: Run Komac in dry-run mode to generate the new manifest locally.
    $komacUpdateArgs = @(
        "update", $WingetId,
        "--version", "$NewVersion",
        "--dry-run",
        "--output", $OutputFolder
    )
    foreach ($url in $InstallerUrls) {
        $komacUpdateArgs += "--urls"
        $komacUpdateArgs += $url
    }
    Write-Host "Running Komac dry-run with arguments: $komacUpdateArgs"
    & $KomacPath @komacUpdateArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Komac dry-run update failed with exit code $LASTEXITCODE"
        return "FAILED_TO_CREATE_PR"
    }
    
    # STEP 2: Locate and load the generated manifest file.
    $installerFileObj = Get-ChildItem -Path $OutputFolder -Recurse -Filter *.installer.yaml | Select-Object -First 1
    if (-not $installerFileObj) {
        Write-Warning "No installer manifest file found in $OutputFolder"
        return "FAILED_TO_CREATE_PR"
    }
    $manifestYaml = Get-Content -Path $installerFileObj.FullName -Raw
    $manifestObj = ConvertFrom-Yaml $manifestYaml
    if (-not $manifestObj.Installers) {
        Write-Warning "No installer entries found in the generated manifest."
        return "FAILED_TO_CREATE_PR"
    }
    
    # STEP 2A: For each old installer entry, force the matching new manifest entry to have the same architecture.
    foreach ($oldInst in $OldInstallers) {
        $oldArch = $oldInst.Architecture
        # Try to find a new installer whose InstallerUrl (or candidate name) matches the old installer architecture.
        # We assume that Find-NewAssetUrlHybrid already handled updating the URL,
        # so here we simply check for any new installer with a matching architecture marker.
        $matchingNew = $manifestObj.Installers | Where-Object {
            $newArch = $_.Architecture
            # Compare in a case-insensitive manner.
            $newArch.ToLower() -eq $oldArch.ToLower()
        } | Select-Object -First 1
        if ($matchingNew) {
            Write-Host "Forcing architecture for $WingetId Setting new installer ($($matchingNew.InstallerUrl)) architecture to $oldArch"
            $matchingNew.Architecture = $oldArch
        }
        else {
            Write-Warning "No new installer found for architecture $oldArch in $WingetId"
        }
    }
    
    # STEP 2B: Write the updated manifest back to disk.
    $updatedYaml = ConvertTo-Yaml $manifestObj
    $updatedYaml | Out-File $installerFileObj.FullName -Force -Encoding UTF8
    Write-Host "Architecture fix complete. Updated manifest saved at: $($installerFileObj.FullName)"
    
    # STEP 3: Submit the updated manifest using Komac submit.
    $komacSubmitArgs = @("submit", $OutputFolder, "--yes")
    if ($OpenPr) { $komacSubmitArgs += "--open-pr" }
    if ($GitHubToken) {
        $komacSubmitArgs += "--token"
        $komacSubmitArgs += $GitHubToken
    }
    Write-Host "Submitting updated manifest with arguments: $komacSubmitArgs"
    & $KomacPath @komacSubmitArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Komac submit failed with exit code $LASTEXITCODE"
        return "FAILED_TO_CREATE_PR"
    }
    return "CREATED_NEW_PR"
}
##############################################################################
# 5. Main Loop
##############################################################################
foreach ($wingetId in $wingetIds) {
    # Check last-checked
    if ($lastCheckedMap.ContainsKey($wingetId)) {
        $lastTime = [datetime]$lastCheckedMap[$wingetId]
        $hoursSince = (Get-Date) - $lastTime
        if ($hoursSince.TotalHours -lt $SkipHours) {
            Write-Host "`n=== Skipping $wingetId last checked $($hoursSince.TotalHours.ToString("F1")) hours ago (< $SkipHours h)."
            continue
        }
    }

    Write-Host "`n=== Checking $wingetId ==="
    Start-Sleep -Seconds 5

    # NEW STEP: Check if an open PR already exists for this package
    $prExists = Get-ExistingPRs -PackageId $wingetId -GitHubToken $GitHubToken
    if ($prExists) {
        Write-Host "An open PR already exists for $wingetId. Skipping update."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    

    # STEP 1: Get the current version from the Winget module
    $existingWingetVerString = Get-CurrentWingetVersion -WingetID $wingetId
    [Version]$existingWingetVersion = $null
    if ($existingWingetVerString) {
        try {
            $existingWingetVersion = [Version]$existingWingetVerString
        }
        catch {
            Write-Host "Winget version '$existingWingetVerString' not parseable. Continuing without installed version."
        }
    }
    if ($existingWingetVersion) {
        Write-Host "Winget thinks $wingetId has version $existingWingetVersion"
    }
    else {
        Write-Host "No Winget record for $wingetId"
    }

    # STEP 2: Retrieve the old manifest from winget-pkgs repo
    $oldManifestYaml = Get-InstallerManifestFromWingetPkgs -PackageId $wingetId -GitHubToken $GitHubToken
    if (-not $oldManifestYaml) {
        Write-Host "No installer manifest found for $wingetId. Skipping."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    try {
        $oldManifestObj = ConvertFrom-Yaml $oldManifestYaml
    }
    catch {
        Write-Warning "Failed to parse old manifest for $wingetId. $_"
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    if (-not $oldManifestObj.PackageVersion) {
        Write-Host "Old manifest missing PackageVersion for $wingetId. Skipping."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }

    # New check: If the version string does not contain a dot, skip this package
    if ($oldManifestObj.PackageVersion -notmatch '\.') {
        Write-Host "Skipping $wingetId because manifest version '$($oldManifestObj.PackageVersion)' is not in a valid format."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }

    [Version]$manifestVersionFromRepo = [Version]$oldManifestObj.PackageVersion

    # Use the installed Winget version if available and higher than manifest version
    if ($existingWingetVersion -and $existingWingetVersion -gt $manifestVersionFromRepo) {
        Write-Host "Installed version ($existingWingetVersion) is higher than manifest version ($manifestVersionFromRepo)."
        $oldWingetVersion = $existingWingetVersion
    }
    else {
        $oldWingetVersion = $manifestVersionFromRepo
    }
    Write-Host "Old version used for comparison: $oldWingetVersion"

    # STEP 3: Parse GH repo from an old installer URL
    $ownerRepo = $null
    foreach ($installer in $oldManifestObj.Installers) {
        $testUrl = $installer.InstallerUrl
        $tmp = ParseOwnerRepoFromGitHubUrl -Url $testUrl
        if ($tmp) {
            $ownerRepo = $tmp
            break
        }
    }
    if (-not $ownerRepo) {
        Write-Host "Could not parse a valid GH repo from old installer URLs for $wingetId. Skipping."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    Write-Host "Detected GH repo: $ownerRepo"

    # STEP 4: Fetch the GitHub latest release for that repo
    $latestRelease = Get-GitHubLatestRelease -OwnerRepo $ownerRepo -GitHubToken $GitHubToken
    if (-not $latestRelease) {
        Write-Host "No GitHub release info for $ownerRepo. Skipping."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    $latestVersion = Convert-ToVersionOrNull -TagName $latestRelease.tag_name
    if (-not $latestVersion) {
        Write-Host "Cannot parse numeric version from GH tag '$($latestRelease.tag_name)' for $wingetId. Skipping."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    Write-Host "GitHub latest release version: $latestVersion"

    # STEP 5: Decide whether to update.
    if ($existingWingetVersion -and $existingWingetVersion -ge $latestVersion) {
        Write-Host "Winget already has version $existingWingetVersion which is >= GH's $latestVersion. Skipping update for $wingetId."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    if ($latestVersion -le $oldWingetVersion) {
        Write-Host "No new version detected. Old: $oldWingetVersion vs. GH: $latestVersion for $wingetId. Skipping."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    Write-Host "Newer version detected: $latestVersion."

    # STEP 6: For each installer in the old manifest, find a matching new asset URL from the GH release assets.
    $newInstallerUrls = @()
    $missingCount = 0
    foreach ($oldInstaller in $oldManifestObj.Installers) {
        $urlMatch = Find-NewAssetUrlHybrid `
            -oldInstaller $oldInstaller `
            -newVersion $latestVersion `
            -assets $latestRelease.assets
        if ($urlMatch) {
            $newInstallerUrls += $urlMatch
        }
        else {
            Write-Warning "Missing asset for architecture '$($oldInstaller.Architecture)' in $wingetId. Skipping update."
            $missingCount++
            break
        }
    }
    if ($missingCount -gt 0 -or $newInstallerUrls.Count -eq 0) {
        Write-Host "Skipping $wingetId because not all installer architectures were found."
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        continue
    }
    Write-Host "Found $($newInstallerUrls.Count) new installer URL(s) for $wingetId"

    # STEP 7: Call Komac to update, fix manifest architecture, and submit the PR.
    $updateResult = Fix-KomacManifestsAndSubmit `
        -KomacPath $KomacPath `
        -WingetId $wingetId `
        -NewVersion $latestVersion `
        -InstallerUrls $newInstallerUrls `
        -OldInstallers $oldManifestObj.Installers `
        -GitHubToken $GitHubToken `
        -OpenPr
    Write-Host "Update result for $wingetId $updateResult"
    $lastCheckedMap[$wingetId] = (Get-Date)
    Save-LastChecked $lastCheckedMap $LastCheckedFile
}

Write-Host "`n=== Done scanning Winget IDs ==="
