# CheckAndUpdateFromWingetManifest

## Overview

This repository contains a suite of PowerShell scripts designed to automate the process of updating Winget package manifests. The main script, `CheckAndUpdateFromWingetManifest.ps1`, performs the following tasks:

- **Version Comparison:**  
  It reads a list of Winget package IDs from a text file and uses the Winget PowerShell module (e.g. PSWinget) to determine the currently installed version for each package. It then retrieves the corresponding manifest from the [Winget-Pkgs repository](https://github.com/microsoft/winget-pkgs) and compares the version against the latest GitHub release.

- **Asset Matching:**  
  If a newer version is detected, the script attempts to find matching installer assets from the GitHub release using a hybrid matching algorithm that first tries direct version substitution and then falls back to pattern-based matching.

- **Manifest Update via Komac:**  
  The script leverages the Komac CLI to update the local Winget manifest. It fixes any architecture mismatches (ensuring, for example, that if the old manifest had a 64‑bit installer, the updated manifest also lists a 64‑bit installer) and then automatically submits a pull request to the winget‑pkgs repository.

- **PR Checking:**  
  Before attempting an update, the script checks if there’s already an open PR for that package update. This prevents duplicate updates.

- **State Management:**  
  The script uses a JSON file (`last_checked.json`) to track when each package was last checked, so that packages aren’t re‑checked more frequently than a specified interval (default 24 hours).

## Requirements

- **PowerShell 7+** (Windows recommended)
- A Winget PowerShell module (e.g., [PSWinget](https://www.powershellgallery.com/packages/PSWinget/))
- The `powershell-yaml` module for parsing YAML manifests
- Komac CLI installed (e.g. at `C:\Program Files\Komac\bin\Komac.exe`)
- A GitHub Personal Access Token (PAT) with minimal required scopes (ideally, `public_repo`)
- Repository secrets configured in GitHub Actions (see Setup below)

## Setup

1. **Repository Files & Folders:**  
   Inside the `Scripts` folder of this repository, include:
   - `winget_ids.txt` – A text file with one Winget package ID per line.
   - `last_checked.json` – A JSON file that will track when packages were last processed.
   - The `komac` folder – This folder contains any additional resources required by Komac.

2. **GitHub Secrets:**  
   In your repository settings, navigate to **Settings > Secrets and variables > Actions** and add a secret named `PAT_TOKEN` with your GitHub PAT. Ensure that the token has only the minimal permissions needed (e.g., the `public_repo` scope).

3. **GitHub Actions Workflow:**  
   A sample GitHub Actions workflow is provided in the repository under `.github/workflows/update-winget-manifests.yml`. This workflow:
   - Checks out the repository.
   - Copies the necessary files (from the `Scripts` folder) to the workspace.
   - Installs required PowerShell modules.
   - Runs the update script.
   - (If changes are made, it commits the updated `last_checked.json` and `komac` folder back to the repository.)

## How It Works

1. **Version Checking:**  
   The script first retrieves the installed version via the Winget module. It then fetches the current manifest version from the Winget-Pkgs repo. If the installed version is higher than the manifest, that version is used for further comparisons.

2. **GitHub Release Comparison:**  
   The script then checks the GitHub repository (parsed from the old manifest's installer URL) for the latest release. If a newer version is available, it continues to update.

3. **Asset Matching:**  
   For each installer defined in the old manifest, the script attempts to find a corresponding asset in the GitHub release assets. If any required asset is missing, the update for that package is skipped.

4. **Manifest Update via Komac:**  
   Komac is used to generate a new manifest (in dry-run mode first) and then to fix any mismatches in installer architecture. Once the manifest is fixed, Komac submits a pull request automatically.

5. **PR Checking:**  
   Before performing an update, the script checks for an existing open PR (using a normalized branch naming convention) to prevent duplicate updates.

## Removal Requests

If you are the author of a GitHub package and wish to have your package removed from manifest updates, please request removal by contacting the repository maintainers with your Winget package ID. This ensures that your package is not automatically updated without your consent.

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request with your changes.

## Disclaimer

This script is provided "as is" without warranty of any kind. Use at your own risk. The maintainers are not responsible for any damage or data loss that may occur due to the use of this script.
