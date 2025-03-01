Param(
    [string]$WingetIdsFile      = ".\winget_ids.txt",        
    [string]$GitHubToken        = ${env:PAT_TOKEN},          # GitHub personal access token
    [string]$KomacPath          = "C:\Program Files\Komac\bin\Komac.exe",
    [string]$LastCheckedFile    = ".\last_checked.json",     # store Winget IDs + last-check times
    [int]$SkipHours             = 120,
    [string]$gptKey             = ${env:OPENAI_KEY},
    [string]$LogFile            = ".\winget_updater.log",
    [int]$MaxRetries            = 3,                         # Maximum number of retries for network operations
    [int]$RetryDelaySeconds     = 5,                         # Delay between retries
    [switch]$EnableVerboseMode  = $false,                    # Enable verbose logging
    [switch]$DryRun             = $false                     # Run without submitting PRs
)

##############################################################################
# Improved Logging
##############################################################################
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")][string]$Level = "INFO",
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Only write DEBUG messages if verbose mode is enabled
    if ($Level -eq "DEBUG" -and -not $EnableVerboseMode) {
        return
    }
    
    # Choose color based on level
    $consoleColor = switch ($Level) {
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "DEBUG"   { "Cyan" }
        default   { "White" }
    }
    
    # Write to console unless suppressed
    if (-not $NoConsole) {
        Write-Host $logMessage -ForegroundColor $consoleColor
    }
    
    # Always write to log file
    try {
        Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8
    }
    catch {
        # If we can't write to the log file, at least show that error on console
        if (-not $NoConsole) {
            Write-Host "Failed to write to log file: $_" -ForegroundColor Red
        }
    }
}

##############################################################################
# Retry Logic for Network Operations
##############################################################################
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$OperationName = "Operation",
        [int]$MaxRetries = $script:MaxRetries,
        [int]$DelaySeconds = $script:RetryDelaySeconds
    )
    
    $retryCount = 0
    $completed = $false
    $result = $null
    
    while (-not $completed -and $retryCount -le $MaxRetries) {
        try {
            if ($retryCount -gt 0) {
                Write-Log "Retry $retryCount/$MaxRetries for $OperationName" -Level DEBUG
            }
            
            $result = Invoke-Command -ScriptBlock $ScriptBlock
            $completed = $true
        }
        catch {
            $retryCount++
            $errorMessage = $_.Exception.Message
            
            # Check for rate limiting
            $isRateLimited = $errorMessage -match "rate limit" -or $_.Exception.Response.StatusCode -eq 429
            
            if ($retryCount -le $MaxRetries) {
                $waitTime = if ($isRateLimited -and $_.Exception.Response.Headers["Retry-After"]) {
                    # Use the Retry-After header if available (GitHub provides this)
                    [int]$_.Exception.Response.Headers["Retry-After"] + 1
                } else {
                    # Otherwise use exponential backoff
                    [Math]::Pow(2, $retryCount) * $DelaySeconds
                }
                
                Write-Log "$OperationName failed with: $errorMessage. Waiting $waitTime seconds before retry." -Level WARNING
                Start-Sleep -Seconds $waitTime
            }
            else {
                Write-Log "$OperationName failed after $MaxRetries retries: $errorMessage" -Level ERROR
                throw $_
            }
        }
    }
    
    return $result
}

##############################################################################
# Enhanced "last-checked" state management
##############################################################################
[Hashtable]$lastCheckedMap = @{}
function Initialize-LastCheckedState {
    if (Test-Path $LastCheckedFile) {
        try {
            $jsonContent = Get-Content $LastCheckedFile -Raw
            if (-not [string]::IsNullOrWhiteSpace($jsonContent)) {
                $tempObj = $jsonContent | ConvertFrom-Json
                if ($tempObj) {
                    foreach ($prop in $tempObj.PSObject.Properties) {
                        $lastCheckedMap[$prop.Name] = $prop.Value
                    }
                }
                Write-Log "Loaded last-checked state for $($lastCheckedMap.Count) packages" -Level INFO
            }
            else {
                Write-Log "Last-checked file exists but is empty. Starting with fresh state." -Level WARNING
            }
        }
        catch {
            Write-Log "Failed to load last-checked state from $LastCheckedFile $_" -Level ERROR
        }
    }
    else {
        Write-Log "No previous last-checked state found. Starting with fresh state." -Level INFO
    }
}

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
        $jsonContent = $psObj | ConvertTo-Json -Depth 5
        $jsonContent | Out-File $Path -Force -Encoding UTF8
        Write-Log "Successfully saved last-checked state for $($Map.Count) packages" -Level DEBUG
    }
    catch {
        Write-Log "Failed to write last-checked state to $Path $_" -Level ERROR
    }
}

##############################################################################
# Enhanced GitHub API interactions with improved error handling
##############################################################################
function Get-GitHubApiResult {
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$GitHubToken,
        [string]$OperationName = "GitHub API request",
        [switch]$RawOutput,
        [hashtable]$AdditionalHeaders = @{}
    )
    
    $headers = @{ "User-Agent" = "WingetManifestUpdater/2.0" }
    
    # Add GitHub token if provided
    if ($GitHubToken) {
        $headers["Authorization"] = "Bearer $GitHubToken"
    }
    
    # Add any additional headers
    foreach ($key in $AdditionalHeaders.Keys) {
        $headers[$key] = $AdditionalHeaders[$key]
    }
    
    # Invoke the API with retry logic
    $result = Invoke-WithRetry -ScriptBlock {
        $response = Invoke-RestMethod -Uri $Url -Headers $headers -Method GET
        
        # Add a small delay to avoid hitting rate limits
        Start-Sleep -Milliseconds 100
        
        # Return raw response or custom object
        if ($RawOutput) {
            return $response
        }
        else {
            return [PSCustomObject]@{
                StatusCode = 200  # Assume success since no exception thrown
                Headers = $response.Headers
                Body = $response
            }
        }
    } -OperationName $OperationName
    
    return $result
}

##############################################################################
# Improved module and dependency checking
##############################################################################
function Initialize-Environment {
    # Check if the Winget IDs file exists
    if (-not (Test-Path $WingetIdsFile)) {
        Write-Log "Winget IDs file '$WingetIdsFile' not found." -Level ERROR
        exit 1
    }
    
    # Check if Komac exists
    if (-not (Test-Path $KomacPath)) {
        Write-Log "Komac tool not found at '$KomacPath'." -Level ERROR
        exit 1
    }

    # Ensure Winget module is available
    if (-not (Get-Module -ListAvailable -Name PSWinget) -and -not (Get-Command Find-WinGetPackage -ErrorAction SilentlyContinue)) {
        Write-Log "Required Winget PowerShell module not found. Installing..." -Level WARNING
        try {
            Install-Module -Name PSWinget -Scope CurrentUser -Force
            Write-Log "PSWinget module installed successfully." -Level SUCCESS
        }
        catch {
            Write-Log "Failed to install PSWinget module: $_" -Level ERROR
            Write-Log "Please install a Winget PowerShell module that provides Find-WinGetPackage." -Level ERROR
            exit 1
        }
    }

    # Ensure powershell-yaml is installed
    if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
        Write-Log "Required powershell-yaml module not found. Installing..." -Level WARNING
        try {
            Install-Module -Name powershell-yaml -Scope CurrentUser -Force
            Write-Log "powershell-yaml module installed successfully." -Level SUCCESS
        }
        catch {
            Write-Log "Failed to install powershell-yaml module: $_" -Level ERROR
            exit 1
        }
    }
    
    try {
        Import-Module powershell-yaml -ErrorAction Stop
        Write-Log "Successfully imported powershell-yaml module" -Level DEBUG
    }
    catch {
        Write-Log "Failed to import powershell-yaml module: $_" -Level ERROR
        exit 1
    }
    
    # Validate GitHub token
    if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
        Write-Log "No GitHub token provided. API rate limits will be lower and PRs can't be created." -Level WARNING
    }
    else {
        Write-Log "GitHub token provided. Will use for API calls and PR creation." -Level DEBUG
    }
    
    # Validate GPT API key
    if ([string]::IsNullOrWhiteSpace($gptKey)) {
        Write-Log "No OpenAI API key provided. Cannot use GPT for URL matching." -Level WARNING
    }
    
    # Load Winget IDs
    $wingetIds = Get-Content $WingetIdsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }
    if ($wingetIds.Count -eq 0) {
        Write-Log "No Winget IDs found in '$WingetIdsFile'. Exiting." -Level ERROR
        exit 0
    }
    
    Write-Log "Found $($wingetIds.Count) Winget IDs to check" -Level SUCCESS
    return $wingetIds
}

##############################################################################
# Improved Winget version retrieval
##############################################################################
function Get-CurrentWingetVersion {
    param(
        [Parameter(Mandatory)][string]$WingetID
    )
    
    try {
        $result = Invoke-WithRetry -ScriptBlock {
            $pkg = Find-WinGetPackage -ID $WingetID -Source winget -ErrorAction Stop | 
                   Select-Object -First 1
            
            if ($pkg) { 
                return [PSCustomObject]@{
                    Success = $true
                    Version = $pkg.Version
                    Name = $pkg.Name
                }
            }
            else {
                return [PSCustomObject]@{
                    Success = $false
                    ErrorMessage = "Package not found"
                }
            }
        } -OperationName "Winget package lookup for $WingetID"
        
        if ($result.Success) {
            Write-Log "Found Winget package: $($result.Name), Version: $($result.Version)" -Level DEBUG
            return $result.Version
        }
        else {
            Write-Log "Package not found in Winget: $WingetID" -Level WARNING
            return $null
        }
    }
    catch {
        Write-Log "Failed to query Winget for $WingetID $_" -Level ERROR
        return $null
    }
}

##############################################################################
# Improved manifest retrieval from GitHub
##############################################################################
function Get-InstallerManifestFromWingetPkgs {
    param(
        [Parameter(Mandatory)][string]$PackageId,
        [string]$GitHubToken
    )
    
    # First, check if manifest exists using manifest search
    $searchString = "PackageIdentifier: $PackageId ManifestType: installer"
    $encoded = [System.Web.HttpUtility]::UrlEncode($searchString)
    $searchUrl = "https://api.github.com/search/code?q=$encoded+in:file+repo:microsoft/winget-pkgs"
    
    try {
        $searchResponse = Get-GitHubApiResult -Url $searchUrl -GitHubToken $GitHubToken -OperationName "GitHub search for $PackageId manifest" -RawOutput
        
        if ($searchResponse.total_count -eq 0) {
            Write-Log "No manifest found for $PackageId in winget-pkgs repository" -Level WARNING
            return $null
        }
        
        # Sort by version to get the latest one
        $sorted = $searchResponse.items | ForEach-Object {
            $v = Get-VersionFromPath $_.path
            if ($v) {
                [PSCustomObject]@{
                    item = $_
                    version = $v
                }
            }
        } | Sort-Object -Property version -Descending
        
        if ($sorted.Count -eq 0) {
            Write-Log "No valid versioned manifests found for $PackageId" -Level WARNING
            return $null
        }
        
        $bestMatch = $sorted[0].item
        Write-Log "Found manifest file at $($bestMatch.path)" -Level DEBUG
        
        # Convert GitHub HTML URL to raw URL
        $rawUrl = $bestMatch.html_url -replace "github.com/microsoft/winget-pkgs/blob", "raw.githubusercontent.com/microsoft/winget-pkgs"
        Write-Log "Raw manifest URL => $rawUrl" -Level DEBUG
        
        # Fetch the actual manifest content
        $manifestContent = Get-GitHubApiResult -Url $rawUrl -GitHubToken $GitHubToken -OperationName "Fetching manifest for $PackageId" -RawOutput
        return $manifestContent
    }
    catch {
        Write-Log "Failed to retrieve manifest for $PackageId $_" -Level ERROR
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
        return [Version]$verString
    }
    catch {
        # Try to clean the version string first
        $cleanVer = $verString -replace '[^0-9\.]', ''
        try {
            return [Version]$cleanVer
        }
        catch {
            Write-Log "Could not parse version from path component: $verString" -Level DEBUG
            return $null
        }
    }
}

##############################################################################
# Enhanced GitHub repository parsing
##############################################################################
function Get-OwnerRepoFromUrl {
    param([string]$Url)
    
    # Match GitHub release download URLs
    if ($Url -match 'https://github\.com/([^/]+)/([^/]+)/releases/download') {
        return "$($matches[1])/$($matches[2])"
    }
    
    # Match GitHub raw content URLs
    if ($Url -match 'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/') {
        return "$($matches[1])/$($matches[2])"
    }
    
    # Match GitHub URLs with blob or tree
    if ($Url -match 'https://github\.com/([^/]+)/([^/]+)(?:/(?:blob|tree)/|$)') {
        return "$($matches[1])/$($matches[2])"
    }
    
    return $null
}

##############################################################################
# Improved GitHub release retrieval
##############################################################################
function Get-GitHubLatestRelease {
    param(
        [Parameter(Mandatory)][string]$OwnerRepo,
        [string]$GitHubToken
    )
    
    $url = "https://api.github.com/repos/$OwnerRepo/releases/latest"
    
    try {
        $release = Get-GitHubApiResult -Url $url -GitHubToken $GitHubToken -OperationName "Getting latest release for $OwnerRepo" -RawOutput
        
        if (-not $release -or -not $release.tag_name) {
            Write-Log "No valid release found for $OwnerRepo" -Level WARNING
            return $null
        }
        
        Write-Log "Latest release for $OwnerRepo $($release.tag_name) with $($release.assets.Count) assets" -Level DEBUG
        return $release
    }
    catch {
        Write-Log "Failed to retrieve latest release for $OwnerRepo $_" -Level ERROR
        
        # If we got a 404, check if there are any releases at all
        if ($_.Exception.Response.StatusCode -eq 404) {
            try {
                $allReleasesUrl = "https://api.github.com/repos/$OwnerRepo/releases"
                $allReleases = Get-GitHubApiResult -Url $allReleasesUrl -GitHubToken $GitHubToken -OperationName "Getting all releases for $OwnerRepo" -RawOutput
                
                if ($allReleases -and $allReleases.Count -gt 0) {
                    Write-Log "No 'latest' release tag but found $($allReleases.Count) regular releases. Using first one." -Level WARNING
                    return $allReleases[0]
                }
            }
            catch {
                Write-Log "Failed to retrieve all releases for $OwnerRepo $_" -Level ERROR
            }
        }
        
        return $null
    }
}

##############################################################################
# Enhanced version parsing and comparison
##############################################################################
function Convert-ToVersion {
    param(
        [Parameter(Mandatory)][string]$TagName,
        [switch]$AllowPartial
    )
    
    $raw = $TagName.Trim().TrimStart('v')
    
    # If it contains non-numeric suffixes, extract just the version part
    $versionRegex = '(\d+(?:\.\d+)*)'
    if ($raw -match $versionRegex) {
        $versionPart = $matches[1]
    }
    else {
        return $null
    }
    
    # Ensure we have at least a major.minor format
    if ($AllowPartial) {
        # Convert single number to x.0 format
        if ($versionPart -match '^\d+$') {
            $versionPart = "$versionPart.0"
        }
    }
    
    try {
        return [Version]$versionPart
    }
    catch {
        Write-Log "Could not parse version from '$TagName' (cleaned to '$versionPart')" -Level DEBUG
        return $null
    }
}

function AreVersionsEqualIgnoringTrailingZeros {
    param(
        [Parameter(Mandatory)][string]$Version1,
        [Parameter(Mandatory)][string]$Version2
    )
    
    $v1 = Remove-TrailingZerosFromVersionString $Version1
    $v2 = Remove-TrailingZerosFromVersionString $Version2
    
    return ($v1 -eq $v2)
}

function Remove-TrailingZerosFromVersionString {
    param(
        [Parameter(Mandatory)][string]$VersionString
    )
    
    # Clean up the version string
    $raw = $VersionString.Trim().TrimStart('v')
    $raw = $raw -replace '[^0-9\.]', ''
    
    if (-not $raw) {
        return $VersionString  # if empty, just return original
    }
    
    # Split into parts
    $parts = $raw.Split('.', [System.StringSplitOptions]::RemoveEmptyEntries)
    
    # Remove trailing "0" parts as long as there's more than 1 part
    while ($parts.Count -gt 1 -and $parts[$parts.Count - 1] -eq '0') {
        $parts = $parts[0..($parts.Count - 2)]
    }
    
    return $parts -join '.'
}

##############################################################################
# Enhanced PR check with improved duplicate detection
##############################################################################
function Get-ExistingPRs {
    param(
        [Parameter(Mandatory)][string]$PackageId,
        [string]$GitHubToken,
        [Version]$NewVersion = $null
    )
    
    # Search open PRs in the winget-pkgs repo
    $prUrl = "https://api.github.com/search/issues?q=repo:microsoft/winget-pkgs+is:pr+is:open+$PackageId+in:title"
    
    try {
        $searchResult = Get-GitHubApiResult -Url $prUrl -GitHubToken $GitHubToken -OperationName "Searching for open PRs for $PackageId" -RawOutput
        
        if ($searchResult.total_count -eq 0) {
            Write-Log "No open PRs found for $PackageId" -Level DEBUG
            return $false
        }
        
        Write-Log "Found $($searchResult.total_count) potential PRs for $PackageId. Checking..." -Level INFO
        
        # Define patterns to match PR titles
        $basicPattern = "^(Update|New)\s+(version|manifest):\s*" + [Regex]::Escape($PackageId) + "\s+.*"
        $versionPattern = "^(Update|New)\s+(version|manifest):\s*" + [Regex]::Escape($PackageId) + "\s+.*(?:to\s+|version\s+)([\d\.]+)"
        
        foreach ($item in $searchResult.items) {
            $title = $item.title
            
            # First check for a basic match
            if ($title -match $basicPattern) {
                Write-Log "Found open PR with title: $title" -Level INFO
                
                # If we're checking for a specific version
                if ($NewVersion) {
                    if ($title -match $versionPattern) {
                        $prVersion = $matches[3]
                        try {
                            $prVersionObj = [Version]$prVersion
                            
                            # If the PR is for the same or newer version, consider it a duplicate
                            if ($prVersionObj -ge $NewVersion) {
                                Write-Log "PR is for version $prVersionObj, which is >= our target $NewVersion" -Level WARNING
                                return $true
                            }
                            else {
                                Write-Log "PR is for version $prVersionObj, which is older than our target $NewVersion" -Level DEBUG
                            }
                        }
                        catch {
                            # If we can't parse the version, be cautious and assume it's a duplicate
                            Write-Log "Couldn't parse version from PR title, assuming duplicate to be safe" -Level WARNING
                            return $true
                        }
                    }
                    else {
                        # If we couldn't extract a version but the package ID matches, be cautious
                        Write-Log "PR title matches package ID but couldn't extract version. Assuming duplicate." -Level WARNING
                        return $true
                    }
                }
                else {
                    # If we're not checking for a specific version, any matching PR is a duplicate
                    return $true
                }
            }
        }
        
        return $false
    }
    catch {
        Write-Log "Failed to check for existing PRs for $PackageId $_" -Level ERROR
        
        # Be cautious and assume there might be a duplicate to avoid creating multiple PRs
        return $true
    }
}

##############################################################################
# Improved GPT-based asset URL matching
##############################################################################
function Get-NewAssetUrlWithGPT {
    param(
        [Parameter(Mandatory)][string]$OldInstallerUrl,
        [Parameter(Mandatory)][string]$OldArchitecture,
        [Parameter(Mandatory)][string]$NewVersion,
        [Parameter(Mandatory)][System.Object[]]$AllAssets,
        [Parameter(Mandatory)][string]$OpenAiKey
    )
    
    # Convert the release assets into a text list
    $assetsListText = $AllAssets | ForEach-Object {
        "- Name: $($_.name), URL: $($_.browser_download_url), Size: $($_.size) bytes"
    } | Out-String
    
    # Extract the old installer filename from URL
    $oldFilename = $OldInstallerUrl -replace '^.*/([^/]+)$', '$1'
    
    $systemMessage = @"
You are a PowerShell assistant that updates installer URLs for Winget package manifests.
Given:
 - The old installer URL and filename
 - The old installer architecture (e.g., x86, x64, arm64)
 - The new version number
 - A list of all available GitHub release assets (filename + URL + size)

Your task is to find the most appropriate new download URL that corresponds to the old installer but for the new version.
Consider these factors when matching:
1. Architecture matching is critical - the new file MUST be for the same architecture
2. Installer type should match (e.g., .exe, .msi, .msix, etc.)
3. Language/locale should match if applicable
4. Installation scope (user/machine) should match if determinable
5. Installer switches should match if determinable from filename

Output only that direct download URL or the word 'none' if no suitable asset can be determined.
No explanations, just a single line with the chosen URL or 'none'.
"@

    $userPrompt = @"
Old Installer URL: $OldInstallerUrl
Old Installer Filename: $oldFilename
Old Installer Architecture: $OldArchitecture
New version: $NewVersion
List of available GitHub release assets:
$assetsListText

Please output only the single best matching installer URL for the new version (or 'none' if no match is found).
"@

    try {
        $result = Invoke-WithRetry -ScriptBlock {
            $openAiUrl = "https://api.openai.com/v1/chat/completions"
            $headers = @{
                "Content-Type" = "application/json"
                "Authorization" = "Bearer $OpenAiKey"
            }
            
            $body = @{
                "model" = "gpt-4o-mini"
                "messages" = @(
                    @{
                        "role" = "system"
                        "content" = $systemMessage
                    },
                    @{
                        "role" = "user"
                        "content" = $userPrompt
                    }
                )
                "temperature" = 0.2  # Lower temperature for more deterministic results
            } | ConvertTo-Json -Depth 5
            
            $response = Invoke-RestMethod -Uri $openAiUrl -Method POST -Headers $headers -Body $body
            
            if ($response.choices) {
                $output = $response.choices[0].message.content.Trim()
                if ($output -match '^https?://') {
                    return $output
                }
                elseif ($output -eq 'none') {
                    return $null
                }
                else {
                    Write-Log "GPT output is not a valid URL or 'none': $output" -Level WARNING
                    return $null
                }
            }
            return $null
        } -OperationName "GPT URL matching for $OldArchitecture architecture"
        
        return $result
    }
    catch {
        Write-Log "GPT API call failed: $_" -Level ERROR
        return $null
    }
}

function Get-NewAssetUrlFallback {
    param(
        [Parameter(Mandatory)]$OldInstallerUrl,
        [Parameter(Mandatory)][string]$OldArchitecture,
        [Parameter(Mandatory)][string]$NewVersion,
        [Parameter(Mandatory)][System.Object[]]$AllAssets
    )
    
    # Extract filename from old URL
    $oldFilename = $OldInstallerUrl -replace '^.*/([^/]+)$', '$1'
    
    # Try to determine patterns in the filename
    $versionPattern = '[vV]?[\d\.]+(?:[-_][a-zA-Z\d]+)?'
    $cleanedFilename = $oldFilename -replace $versionPattern, '{VERSION}'
    
    Write-Log "Extracted pattern from filename: $cleanedFilename" -Level DEBUG
    
    # Create patterns to search for the new filename
    $patterns = @(
        # Exact same pattern with new version
        ($cleanedFilename -replace '\{VERSION\}', $NewVersion),
        # Version with 'v' prefix
        ($cleanedFilename -replace '\{VERSION\}', "v$NewVersion"),
        # Version only (in case filename pattern completely changed)
        $NewVersion
    )
    
    # Architecture patterns to look for
    $archPatterns = @(
        $OldArchitecture,
        $OldArchitecture.ToLower(),
        $OldArchitecture.ToUpper()
    )
    
    # Special cases for common architectures
    switch ($OldArchitecture.ToLower()) {
        "x64" { $archPatterns += @("amd64", "64bit", "64", "win64") }
        "x86" { $archPatterns += @("32bit", "32", "win32", "i386") }
        "arm64" { $archPatterns += @("aarch64", "arm") }
    }
    
    # Extension pattern
    $extension = [System.IO.Path]::GetExtension($oldFilename)
    
    # Search assets that match our criteria
    $matchedAssets = @()
    foreach ($asset in $AllAssets) {
        $assetName = $asset.name.ToLower()
        $assetUrl = $asset.browser_download_url
        
        # Check if file extension matches
        if (-not [string]::IsNullOrEmpty($extension) -and -not $assetName.EndsWith($extension.ToLower())) {
            continue
        }
        
        # Check for version match
        $versionMatch = $false
        foreach ($pattern in $patterns) {
            if ($assetName -like "*$($pattern.ToLower())*") {
                $versionMatch = $true
                break
            }
        }
        
        if (-not $versionMatch) {
            continue
        }
        
        # Check for architecture match
        $archMatch = $false
        foreach ($archPattern in $archPatterns) {
            if ($assetName -like "*$($archPattern.ToLower())*") {
                $archMatch = $true
                break
            }
        }
        
        if ($archMatch) {
            $matchedAssets += $asset
        }
    }
    
    if ($matchedAssets.Count -eq 0) {
        Write-Log "No matching assets found for $OldArchitecture using pattern matching" -Level WARNING
        return $null
    }
    
    if ($matchedAssets.Count -eq 1) {
        Write-Log "Found exactly one matching asset: $($matchedAssets[0].name)" -Level SUCCESS
        return $matchedAssets[0].browser_download_url
    }
    
    # If multiple matches, pick the one with most filename similarities
    $bestMatch = $matchedAssets | Sort-Object {
        $similarity = [Levenshtein]::ComputeDistance($oldFilename, $_.name)
        # Lower score is better
        return $similarity
    } | Select-Object -First 1
    
    Write-Log "Selected best match from $($matchedAssets.Count) candidates: $($bestMatch.name)" -Level SUCCESS
    return $bestMatch.browser_download_url
}

# Simple Levenshtein distance implementation for string similarity
class Levenshtein {
    static [int] ComputeDistance([string]$source, [string]$target) {
        $n = $source.Length
        $m = $target.Length
        $d = New-Object 'int[,]' ($n+1),($m+1)
        
        if ($n -eq 0) { return $m }
        if ($m -eq 0) { return $n }
        
        for ($i = 0; $i -le $n; $i++) { $d[$i,0] = $i }
        for ($j = 0; $j -le $m; $j++) { $d[0,$j] = $j }
        
        for ($i = 1; $i -le $n; $i++) {
            for ($j = 1; $j -le $m; $j++) {
                $cost = if ($target[$j-1] -eq $source[$i-1]) { 0 } else { 1 }
                $d[$i,$j] = [Math]::Min(
                    [Math]::Min($d[$i-1,$j] + 1, $d[$i,$j-1] + 1),
                    $d[$i-1,$j-1] + $cost
                )
            }
        }
        
        return $d[$n,$m]
    }
}

function Find-NewAssetUrlHybrid {
    param(
        [Parameter(Mandatory)]$oldInstaller,
        [Parameter(Mandatory)][Version]$newVersion,
        [Parameter(Mandatory)]$assets,
        [string]$OpenAiKey = $null
    )
    
    $oldUrl = $oldInstaller.InstallerUrl
    $arch = $oldInstaller.Architecture
    $newVerStr = $newVersion.ToString()
    
    Write-Log "Finding new asset URL for architecture [$arch] (old URL: $oldUrl)" -Level INFO
    
    # Try GPT first if key is provided
    if (-not [string]::IsNullOrWhiteSpace($OpenAiKey)) {
        Write-Log "Using GPT to determine new asset URL" -Level INFO
        $gptUrl = Get-NewAssetUrlWithGPT `
            -OldInstallerUrl $oldUrl `
            -OldArchitecture $arch `
            -NewVersion $newVerStr `
            -AllAssets $assets `
            -OpenAiKey $OpenAiKey
        
        if ($gptUrl) {
            Write-Log "GPT returned URL: $gptUrl" -Level SUCCESS
            return $gptUrl
        }
        else {
            Write-Log "GPT did not return a valid URL. Falling back to pattern matching." -Level WARNING
        }
    }
    else {
        Write-Log "No OpenAI key provided; skipping GPT-based URL generation." -Level DEBUG
    }
    
    # Fallback to pattern matching
    Write-Log "Using pattern matching to find new asset URL" -Level INFO
    $fallbackUrl = Get-NewAssetUrlFallback `
        -OldInstallerUrl $oldUrl `
        -OldArchitecture $arch `
        -NewVersion $newVerStr `
        -AllAssets $assets
    
    if ($fallbackUrl) {
        Write-Log "Pattern matching found URL: $fallbackUrl" -Level SUCCESS
        return $fallbackUrl
    }
    
    Write-Log "Could not determine new asset URL for architecture $arch" -Level ERROR
    return $null
}

##############################################################################
# Enhanced Komac Interaction with Validation
##############################################################################
function Test-ManifestValidity {
    param(
        [Parameter(Mandatory)][string]$ManifestPath
    )
    
    if (-not (Test-Path $ManifestPath)) {
        Write-Log "Manifest file not found at $ManifestPath" -Level ERROR
        return $false
    }
    
    try {
        $manifestContent = Get-Content -Path $ManifestPath -Raw
        $manifestObj = ConvertFrom-Yaml $manifestContent -ErrorAction Stop
        
        # Check required fields
        $requiredFields = @("PackageIdentifier", "PackageVersion", "ManifestType", "ManifestVersion")
        foreach ($field in $requiredFields) {
            if (-not $manifestObj.$field) {
                Write-Log "Manifest missing required field: $field" -Level ERROR
                return $false
            }
        }
        
        # For installer manifests, check installers array
        if ($manifestObj.ManifestType -eq "installer" -and 
            (-not $manifestObj.Installers -or $manifestObj.Installers.Count -eq 0)) {
            Write-Log "Installer manifest has no installers" -Level ERROR
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to validate manifest: $_" -Level ERROR
        return $false
    }
}

function Fix-KomacManifestsAndSubmit {
    param(
        [Parameter(Mandatory)][string]$KomacPath,
        [Parameter(Mandatory)][string]$WingetId,
        [Parameter(Mandatory)][version]$NewVersion,
        [Parameter(Mandatory)][string[]]$InstallerUrls,
        [Parameter(Mandatory)]$OldInstallers,  # Array of installer objects
        [string]$OutputFolder = ".komac/$WingetId",
        [string]$GitHubToken,
        [switch]$DryRun,
        [switch]$OpenPr
    )
    
    # Create uniquely named temp file for capturing output
    $tempOutputFile = [System.IO.Path]::GetTempFileName()
    
    # Clear output folder first if it exists
    if (Test-Path $OutputFolder) {
        try {
            Remove-Item -Path $OutputFolder -Recurse -Force
            Write-Log "Cleared existing output folder: $OutputFolder" -Level DEBUG
        }
        catch {
            Write-Log "Failed to clear output folder: $_" -Level WARNING
        }
    }
    
    # Set GitHub token if provided
    if ($GitHubToken) {
        try {
            & $KomacPath token update --token $GitHubToken
            Write-Log "Successfully updated Komac GitHub token" -Level DEBUG
        }
        catch {
            Write-Log "Failed to update Komac GitHub token: $_" -Level WARNING
        }
    }
    
    # STEP 1: Run Komac in dry-run mode to generate new manifest locally
    $komacUpdateArgs = @("update", $WingetId, "--version", "$NewVersion", "--dry-run", "--output", $OutputFolder)
    foreach ($url in $InstallerUrls) {
        $komacUpdateArgs += "--urls"
        $komacUpdateArgs += $url
    }
    
    Write-Log "Running Komac dry-run with arguments: $($komacUpdateArgs -join ' ')" -Level INFO
    
    try {
        $komacOutput = & $KomacPath @komacUpdateArgs 2>&1
        $komacExitCode = $LASTEXITCODE
        
        # Log the Komac output
        $komacOutput | ForEach-Object {
            Write-Log "Komac: $_" -Level DEBUG -NoConsole
        }
        
        if ($komacExitCode -ne 0) {
            Write-Log "Komac dry-run update failed with exit code $komacExitCode" -Level ERROR
            return "FAILED_TO_CREATE_MANIFEST"
        }
    }
    catch {
        Write-Log "Exception running Komac: $_" -Level ERROR
        return "FAILED_TO_CREATE_MANIFEST"
    }
    
    # STEP 2: Locate and load the generated manifest file
    $installerFileObj = Get-ChildItem -Path $OutputFolder -Recurse -Filter *.installer.yaml | Select-Object -First 1
    if (-not $installerFileObj) {
        Write-Log "No installer manifest file found in $OutputFolder" -Level ERROR
        return "FAILED_TO_FIND_MANIFEST"
    }
    
    # Validate manifest before proceeding
    if (-not (Test-ManifestValidity -ManifestPath $installerFileObj.FullName)) {
        Write-Log "Generated manifest failed validation" -Level ERROR
        return "INVALID_MANIFEST"
    }
    
    try {
        $manifestYaml = Get-Content -Path $installerFileObj.FullName -Raw
        $manifestObj = ConvertFrom-Yaml $manifestYaml -ErrorAction Stop
        
        if (-not $manifestObj.Installers -or $manifestObj.Installers.Count -eq 0) {
            Write-Log "No installer entries found in the generated manifest" -Level ERROR
            return "FAILED_TO_CREATE_MANIFEST"
        }
    }
    catch {
        Write-Log "Failed to parse generated manifest: $_" -Level ERROR
        return "FAILED_TO_PARSE_MANIFEST"
    }
    
    # STEP 2A: For each old installer entry, force the new manifest to have the same architecture
    foreach ($oldInst in $OldInstallers) {
        $oldArch = $oldInst.Architecture
        $matchingNew = $manifestObj.Installers | Where-Object {
            $newArch = $_.Architecture
            $newArch.ToLower() -eq $oldArch.ToLower()
        } | Select-Object -First 1
        
        if ($matchingNew) {
            Write-Log "Forcing architecture for $WingetId => new installer ($($matchingNew.InstallerUrl)) => $oldArch" -Level DEBUG
            $matchingNew.Architecture = $oldArch
        }
        else {
            Write-Log "No new installer found for architecture $oldArch in $WingetId" -Level WARNING
        }
    }
    
    # STEP 2B: Write updated manifest back to disk
    try {
        $updatedYaml = ConvertTo-Yaml $manifestObj
        $updatedYaml | Out-File $installerFileObj.FullName -Force -Encoding UTF8
        Write-Log "Updated manifest saved at: $($installerFileObj.FullName)" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to write updated manifest: $_" -Level ERROR
        return "FAILED_TO_WRITE_MANIFEST"
    }
    
    # If this is just a dry run, stop here
    if ($DryRun -or $script:DryRun) {
        Write-Log "DRY RUN - Skipping PR submission" -Level WARNING
        return "DRY_RUN_COMPLETE"
    }
    
    # STEP 3: Submit the updated manifest using Komac
    $komacSubmitArgs = @("submit", $OutputFolder, "--yes")
    if ($OpenPr) { $komacSubmitArgs += "--open-pr" }
    if ($GitHubToken) {
        $komacSubmitArgs += "--token"
        $komacSubmitArgs += $GitHubToken
    }
    
    Write-Log "Submitting updated manifest with arguments: $($komacSubmitArgs -join ' ')" -Level INFO
    
    try {
        # Redirect all output to both the console and our temp file
        & $KomacPath @komacSubmitArgs 2>&1 | Tee-Object -FilePath $tempOutputFile
        $submitExitCode = $LASTEXITCODE
        
        # Read all output for processing
        $submitOutput = Get-Content -Path $tempOutputFile -Raw
        
        # Log the Komac output
        Write-Log "Komac Submit Output: $submitOutput" -Level DEBUG -NoConsole
        
        if ($submitExitCode -ne 0) {
            Write-Log "Komac submit failed with exit code $submitExitCode" -Level ERROR
            return "FAILED_TO_CREATE_PR"
        }
        
        # Try to extract PR URL from output using improved regex
        if ($submitOutput -match 'https://github\.com/microsoft/winget-pkgs/pull/\d+') {
            $prUrl = $matches[0]
            Write-Log "Created PR: $prUrl" -Level SUCCESS
            return "CREATED_NEW_PR:$prUrl"
        }
        else {
            Write-Log "PR created successfully but couldn't extract URL from output" -Level SUCCESS
            return "CREATED_NEW_PR"
        }
    }
    catch {
        Write-Log "Exception submitting PR: $_" -Level ERROR
        return "FAILED_TO_CREATE_PR"
    }
    finally {
        # Clean up temp file
        if (Test-Path $tempOutputFile) {
            Remove-Item -Path $tempOutputFile -Force -ErrorAction SilentlyContinue
        }
    }
}

##############################################################################
# MAIN PROGRAM
##############################################################################

# Clear or initialize log file
if (-not $EnableVerboseMode) {
    if (Test-Path $LogFile) {
        try {
            Clear-Content $LogFile -Force
        }
        catch {
            # Just create a new file if can't clear
            "# Winget Updater Log - Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $LogFile -Force
        }
    }
    else {
        "# Winget Updater Log - Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $LogFile -Force
    }
}

Write-Log "=== Winget Manifest Updater starting ===" -Level INFO
Write-Log "Script parameters:" -Level DEBUG
Write-Log "- WingetIdsFile: $WingetIdsFile" -Level DEBUG
Write-Log "- KomacPath: $KomacPath" -Level DEBUG
Write-Log "- SkipHours: $SkipHours" -Level DEBUG
Write-Log "- LogFile: $LogFile" -Level DEBUG
Write-Log "- DryRun: $DryRun" -Level DEBUG
Write-Log "- VerboseMode: $EnableVerboseMode" -Level DEBUG
Write-Log "- GitHub Token: $(if ($GitHubToken) { 'Provided' } else { 'Not provided' })" -Level DEBUG
Write-Log "- OpenAI Key: $(if ($gptKey) { 'Provided' } else { 'Not provided' })" -Level DEBUG

# Initialize environment and load Winget IDs
Initialize-LastCheckedState
$wingetIds = Initialize-Environment

# Create a summary report hashtable
$summary = @{
    Checked = 0
    Skipped = 0
    UpToDate = 0
    Updated = 0
    Failed = 0
    PRs = @()
}

# Process each Winget ID
foreach ($wingetId in $wingetIds) {
    $summary.Checked++
    
    # Check if this package was recently checked
    if ($lastCheckedMap.ContainsKey($wingetId)) {
        $lastTime = [datetime]$lastCheckedMap[$wingetId]
        $hoursSince = (Get-Date) - $lastTime
        if ($hoursSince.TotalHours -lt $SkipHours) {
            Write-Log "Skipping $wingetId; last checked $($hoursSince.TotalHours.ToString("F1")) hours ago (< $SkipHours h)" -Level INFO
            $summary.Skipped++
            continue
        }
    }
    
    Write-Log "======== Checking $wingetId ========" -Level INFO
    
    # Check if an open PR already exists for this package
    $prExists = Get-ExistingPRs -PackageId $wingetId -GitHubToken $GitHubToken
    if ($prExists) {
        Write-Log "An open PR already exists for $wingetId. Skipping update." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    # STEP 1: Get the current version from Winget
    $existingWingetVerString = Get-CurrentWingetVersion -WingetID $wingetId
    [Version]$existingWingetVersion = $null
    if ($existingWingetVerString) {
        try {
            $existingWingetVersion = [Version]$existingWingetVerString
            Write-Log "Current Winget version for $wingetId $existingWingetVersion" -Level INFO
        }
        catch {
            Write-Log "Winget version '$existingWingetVerString' not parseable as a version. Continuing without installed version." -Level WARNING
        }
    }
    else {
        Write-Log "No current version found in Winget for $wingetId" -Level INFO
    }
    
    # STEP 2: Retrieve the old manifest
    $oldManifestYaml = Get-InstallerManifestFromWingetPkgs -PackageId $wingetId -GitHubToken $GitHubToken
    if (-not $oldManifestYaml) {
        Write-Log "No installer manifest found for $wingetId. Skipping." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    try {
        $oldManifestObj = ConvertFrom-Yaml $oldManifestYaml -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to parse old manifest for $wingetId $_" -Level ERROR
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Failed++
        continue
    }
    
    if (-not $oldManifestObj.PackageVersion) {
        Write-Log "Old manifest missing PackageVersion for $wingetId. Skipping." -Level ERROR
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Failed++
        continue
    }
    
    [Version]$manifestVersionFromRepo = $null
    try {
        $manifestVersionFromRepo = [Version]$oldManifestObj.PackageVersion
        Write-Log "Manifest version from repository: $manifestVersionFromRepo" -Level INFO
    }
    catch {
        Write-Log "Manifest version '$($oldManifestObj.PackageVersion)' not parseable as a version. Skipping $wingetId." -Level ERROR
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Failed++
        continue
    }
    
    # Decide which old version to compare: installed if higher, else manifest
    if ($existingWingetVersion -and $existingWingetVersion -gt $manifestVersionFromRepo) {
        Write-Log "Installed version ($existingWingetVersion) is higher than manifest version ($manifestVersionFromRepo)." -Level INFO
        $oldWingetVersion = $existingWingetVersion
    }
    else {
        $oldWingetVersion = $manifestVersionFromRepo
    }
    Write-Log "Using version $oldWingetVersion for comparison" -Level INFO
    
    # STEP 3: Parse GitHub repo from an old installer URL
    $ownerRepo = $null
    foreach ($installer in $oldManifestObj.Installers) {
        $testUrl = $installer.InstallerUrl
        $tmp = Get-OwnerRepoFromUrl -Url $testUrl
        if ($tmp) {
            $ownerRepo = $tmp
            break
        }
    }
    
    if (-not $ownerRepo) {
        Write-Log "Could not parse a valid GitHub repo from old installer URLs for $wingetId. Skipping." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    Write-Log "Detected GitHub repo: $ownerRepo" -Level INFO
    
    # STEP 4: Fetch the GitHub latest release
    $latestRelease = Get-GitHubLatestRelease -OwnerRepo $ownerRepo -GitHubToken $GitHubToken
    if (-not $latestRelease) {
        Write-Log "No GitHub release info for $ownerRepo. Skipping." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    # Skip if no assets
    if (-not $latestRelease.assets -or $latestRelease.assets.Count -eq 0) {
        Write-Log "No GitHub release assets found (latest tag is $($latestRelease.tag_name)). Skipping." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    # Parse version from tag
    $latestVersion = Convert-ToVersion -TagName $latestRelease.tag_name -AllowPartial
    if (-not $latestVersion) {
        Write-Log "Cannot parse numeric version from GitHub tag '$($latestRelease.tag_name)' for $wingetId. Skipping." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    Write-Log "GitHub latest release version: $latestVersion" -Level INFO
    
    # STEP 5: Decide whether to update
    if ($existingWingetVersion -and $existingWingetVersion -ge $latestVersion) {
        Write-Log "Winget already has version $existingWingetVersion which is >= GitHub's $latestVersion. No update needed." -Level INFO
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.UpToDate++
        continue
    }
    
    # Check if versions are equal when ignoring trailing zeros
    if (AreVersionsEqualIgnoringTrailingZeros "$($oldWingetVersion.ToString())" "$($latestVersion.ToString())") {
        Write-Log "GitHub version $latestVersion differs only by trailing zeros from $oldWingetVersion. No update needed." -Level INFO
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.UpToDate++
        continue
    }
    
    if ($latestVersion -le $oldWingetVersion) {
        Write-Log "No new version detected. Old: $oldWingetVersion vs. GitHub: $latestVersion. No update needed." -Level INFO
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.UpToDate++
        continue
    }
    
    # A newer version was found
    Write-Log "Newer version detected: $latestVersion > $oldWingetVersion. Preparing update..." -Level SUCCESS
    
    # Double-check no PRs exist for this specific new version
    $versionSpecificPrExists = Get-ExistingPRs -PackageId $wingetId -GitHubToken $GitHubToken -NewVersion $latestVersion
    if ($versionSpecificPrExists) {
        Write-Log "A PR for $wingetId version $latestVersion already exists. Skipping update." -Level WARNING
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Skipped++
        continue
    }
    
    # STEP 6: For each installer in the old manifest, find a matching new asset URL
    $newInstallerUrls = @()
    $missingCount = 0
    foreach ($oldInstaller in $oldManifestObj.Installers) {
        $urlMatch = Find-NewAssetUrlHybrid `
            -oldInstaller $oldInstaller `
            -newVersion $latestVersion `
            -assets $latestRelease.assets `
            -OpenAiKey $gptKey
        
        if ($urlMatch) {
            $newInstallerUrls += $urlMatch
        }
        else {
            Write-Log "Missing asset for architecture '$($oldInstaller.Architecture)' in $wingetId. Cannot create complete manifest." -Level ERROR
            $missingCount++
            break
        }
    }
    
    if ($missingCount -gt 0 -or $newInstallerUrls.Count -eq 0) {
        Write-Log "Skipping $wingetId because not all installer architectures were found." -Level ERROR
        $lastCheckedMap[$wingetId] = (Get-Date)
        Save-LastChecked $lastCheckedMap $LastCheckedFile
        $summary.Failed++
        continue
    }
    
    Write-Log "Found $($newInstallerUrls.Count) new installer URL(s) for $wingetId" -Level SUCCESS
    
    # STEP 7: Call Komac to update, fix manifest architecture, submit PR
    $updateResult = Fix-KomacManifestsAndSubmit `
        -KomacPath $KomacPath `
        -WingetId $wingetId `
        -NewVersion $latestVersion `
        -InstallerUrls $newInstallerUrls `
        -OldInstallers $oldManifestObj.Installers `
        -GitHubToken $GitHubToken `
        -DryRun:$DryRun `
        -OpenPr
    
    Write-Log "Update result for $wingetId $updateResult" -Level INFO
    
    # Parse PR URL if available - fix to handle additional text in the output
    if ($updateResult -match 'CREATED_NEW_PR:(\S+)') {
        # Extract PR URL using more flexible pattern that works even with additional text
        $prUrl = $matches[1]
        $summary.PRs += @{
            PackageId = $wingetId
            NewVersion = $latestVersion.ToString()
            OldVersion = $oldWingetVersion.ToString()
            PrUrl = $prUrl
        }
        $summary.Updated++
    }
    elseif ($updateResult -like "*CREATED_NEW_PR*") {
        # Handle case where PR was created but URL couldn't be extracted
        $summary.PRs += @{
            PackageId = $wingetId
            NewVersion = $latestVersion.ToString()
            OldVersion = $oldWingetVersion.ToString()
            PrUrl = "Unknown URL"
        }
        $summary.Updated++
    }
    elseif ($updateResult -eq "DRY_RUN_COMPLETE") {
        # Count as success for dry runs
        $summary.Updated++
    }
    else {
        $summary.Failed++
    }
    
    # Update last checked time
    $lastCheckedMap[$wingetId] = (Get-Date)
    Save-LastChecked $lastCheckedMap $LastCheckedFile
}

# Output summary
Write-Log "======== Execution Summary ========" -Level INFO
Write-Log "Packages checked: $($summary.Checked)" -Level INFO
Write-Log "Packages skipped: $($summary.Skipped)" -Level INFO
Write-Log "Packages up-to-date: $($summary.UpToDate)" -Level INFO
Write-Log "Packages updated: $($summary.Updated)" -Level SUCCESS
Write-Log "Packages failed: $($summary.Failed)" -Level ($summary.Failed -gt 0 ? "WARNING" : "INFO")

if ($summary.PRs.Count -gt 0) {
    Write-Log "======== Created Pull Requests ========" -Level SUCCESS
    foreach ($pr in $summary.PRs) {
        Write-Log "$($pr.PackageId): $($pr.OldVersion) -> $($pr.NewVersion) ($($pr.PrUrl))" -Level SUCCESS
    }
}

Write-Log "=== Winget Manifest Updater completed ===" -Level INFO