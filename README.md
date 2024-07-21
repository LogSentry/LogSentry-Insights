# Git Workflow PowerShell Script
## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Usage](#usage)
    - [Commands](#commands)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [OAuth Authentication](#oauth-authentication)
    - [Script Functions](#script-functions)
    - [Dependencies](#dependencies)
    - [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contact](#contact)

## Overview

This PowerShell script automates the process of managing Git workflows and integrates with Jira and GitHub. It supports task fetching from Jira, branch management, and pull request creation. Additionally, it handles OAuth authentication and token management securely.

## Features

- **OAuth Authentication**: Handles secure token storage and retrieval for GitHub and Jira.
- **Git Operations**: Automates Git branching, committing, and pull request creation.
- **Jira Integration**: Fetches assigned tasks from Jira, updates task status, and extracts Jira codes from branch names.
- **Setup**: Configures Git aliases and script paths for easy access.

## Usage

### Commands

1. **Start a New Task**

        Starts a new task by fetching an assigned Jira task, creating a new Git branch, and switching to it.

        ```powershell
        .\git-workflow.ps1 get
        ```

2. **Complete the Current Task**

        Commits changes, pushes to GitHub, creates a pull request, and optionally updates the Jira issue status.

        ```powershell
        .\git-workflow.ps1 done
        ```

3. **Setup Git Workflow**

        Configures the environment by creating necessary scripts and updating Git aliases.

        ```powershell
        .\git-workflow.ps1 setup
        ```

### Installation

1. **Clone the Repository**

        Clone this repository to your local machine.

        ```bash
        git clone https://github.com/LogSentry/LogSentry-Insights/tree/test
        ```

2. **Run Setup**

        Execute the setup command to configure Git workflow scripts and aliases.

        ```powershell
        .\git-workflow.ps1 setup
        ```

### Configuration

The script relies on secure token management for GitHub and Jira. Tokens are stored in the user profile directory.

- GitHub Token: Stored as `$env:USERPROFILE\.jira_git_workflow\.github_token`
- Jira Token: Stored as `$env:USERPROFILE\.jira_git_workflow\.jira_token`
- Jira URL: Stored in `$env:USERPROFILE\.jira_git_workflow\config.json`

### OAuth Authentication

On first run, the script will prompt you for your GitHub and Jira OAuth credentials to obtain and store access tokens. Ensure you have OAuth apps set up on both platforms.

### Script Functions

- `Start-NewTask`: Fetches a Jira task, creates a new Git branch, and switches to it.
- `Complete-Task`: Commits and pushes changes, creates a pull request, and updates Jira issue status.
- `Setup-GitWorkflow`: Configures environment scripts and Git aliases.
- `Show-ProgressBar`: Displays a progress bar for script operations.
- `Get-SecureToken`: Retrieves a secure token from storage.
- `Save-SecureToken`: Saves a secure token to storage.
- `Start-OAuthFlow`: Manages OAuth authentication flow.
- `Get-JiraToken`: Retrieves or obtains a Jira token.
- `Get-GithubToken`: Retrieves or obtains a GitHub token.
- `Get-JiraUrl`: Retrieves the Jira URL from configuration or prompts for it.
- `Check-GitRepo`: Verifies if the current directory is a Git repository.
- `Check-And-Set-Origin`: Ensures the correct Git origin is set.
- `Fetch-And-Select-Task`: Fetches assigned Jira tasks and lets the user select one.
- `Create-And-Switch-Branch`: Creates and switches to a new Git branch based on Jira task.
- `Extract-JiraCode`: Extracts Jira code from the current Git branch name.
- `Update-JiraStatus`: Updates the status of a Jira issue.
- `Get-JiraStatus`: Retrieves the current status of a Jira issue.
- `Create-PullRequest`: Creates a GitHub pull request for the current branch.
- `Download-And-Extract`: Downloads and extracts files from Google Drive (external function).
- `Extract-Tar-Gz`: Extracts tar.gz files using multi-threading (external function).

### Dependencies

- PowerShell: Ensure you have PowerShell installed on your system.
- Git: Git must be installed and accessible from the command line.
- OAuth Apps: GitHub and Jira OAuth apps must be configured for token generation.

### Troubleshooting

- Invalid Git Token: Ensure your GitHub and Jira tokens are correctly configured and have the necessary permissions.
- OAuth Errors: Verify OAuth credentials and redirect URIs are correctly set up in your GitHub and Jira applications.
- Branch Name Issues: Ensure branch names are formatted correctly and do not contain illegal characters.

### License

This script is provided as-is without any warranty. You can modify and use it according to your needs.

### Contact

For issues or questions, please open an issue on the [GitHub repository](https://github.com/LogSentry/LogSentry-Insights/tree/test).
