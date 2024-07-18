# git-workflow.ps1

Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security

$configDir = "$env:USERPROFILE\.jira_git_workflow"
$configFile = "$configDir\config.json"
$scriptsDir = "$env:USERPROFILE\GitScripts"

Write-Host "Script started" -ForegroundColor Cyan

function Show-ProgressBar {
    param (
        [int]$PercentComplete,
        [string]$Status
    )
    $width = 50
    $filled = [math]::Round($width * ($PercentComplete / 100))
    $empty = $width - $filled
    $bar = ("[" + "=" * $filled + " " * $empty + "]").PadRight($width + 2)
    Write-Host "`r$bar $PercentComplete% $Status" -NoNewline
}

function Get-Config {
    if (Test-Path $configFile) {
        return Get-Content $configFile | ConvertFrom-Json
    }
    return $null
}

function Save-Config($config) {
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    }
    $config | ConvertTo-Json | Set-Content $configFile
}

function Save-SecureToken {
    param (
        [string]$TokenName,
        [string]$Token
    )
    $secureToken = ConvertTo-SecureString -String $Token -AsPlainText -Force
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $encrypted | Set-Content "$configDir\.$TokenName" -Encoding Byte
}

function Get-SecureToken {
    param (
        [string]$TokenName
    )
    if (Test-Path "$configDir\.$TokenName") {
        $encrypted = Get-Content "$configDir\.$TokenName" -Encoding Byte
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    return $null
}

function Start-OAuthFlow {
    param (
        [string]$AuthUrl,
        [string]$TokenUrl,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$RedirectUri,
        [string]$Scope
    )
    $state = [System.Guid]::NewGuid().ToString()
    $fullAuthUrl = "${AuthUrl}?client_id=${ClientId}&redirect_uri=${RedirectUri}&state=${state}&scope=${Scope}&response_type=code"
    
    # Start local server to listen for the callback
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($RedirectUri)
    $listener.Start()

    # Open the default browser
    Start-Process $fullAuthUrl

    Write-Host "Waiting for authentication in your browser..." -ForegroundColor Cyan

    # Wait for the callback
    $context = $listener.GetContext()
    $requestUrl = $context.Request.Url
    $code = [System.Web.HttpUtility]::ParseQueryString($requestUrl.Query)["code"]

    # Send a response to the browser
    $response = $context.Response
    $responseString = "<html><body><h1>Authentication successful!</h1><p>You can close this window now.</p></body></html>"
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseString)
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.Close()

    $listener.Stop()

    if (-not $code) {
        throw "Failed to obtain authorization code"
    }

    $response = Invoke-RestMethod -Uri $TokenUrl -Method Post -Body @{
        grant_type = "authorization_code"
        client_id = $ClientId
        client_secret = $ClientSecret
        code = $code
        redirect_uri = $RedirectUri
    }
    
    return $response.access_token
}

function Get-GithubToken {
    $token = Get-SecureToken -TokenName "github_token"
    if ($token) {
        Write-Host "Using existing GitHub token" -ForegroundColor Green
        return $token
    }

    $clientId = Read-Host "Enter your GitHub OAuth App Client ID"
    $clientSecret = Read-Host "Enter your GitHub OAuth App Client Secret"
    $redirectUri = "http://localhost:8080/github-callback"

    $token = Start-OAuthFlow -AuthUrl "https://github.com/login/oauth/authorize" `
                             -TokenUrl "https://github.com/login/oauth/access_token" `
                             -ClientId $clientId `
                             -ClientSecret $clientSecret `
                             -RedirectUri $redirectUri `
                             -Scope "repo"

    Save-SecureToken -TokenName "github_token" -Token $token
    return $token
}

function Get-JiraToken {
    $token = Get-SecureToken -TokenName "jira_token"
    if ($token) {
        Write-Host "Using existing Jira token" -ForegroundColor Green
        return $token
    }

    $clientId = Read-Host "Enter your Jira OAuth App Client ID"
    $clientSecret = Read-Host "Enter your Jira OAuth App Client Secret"
    $redirectUri = "http://localhost:8080/jira-callback"

    $token = Start-OAuthFlow -AuthUrl "https://auth.atlassian.com/authorize" `
                             -TokenUrl "https://auth.atlassian.com/oauth/token" `
                             -ClientId $clientId `
                             -ClientSecret $clientSecret `
                             -RedirectUri $redirectUri `
                             -Scope "read:jira-work write:jira-work"

    Save-SecureToken -TokenName "jira_token" -Token $token
    return $token
}

function Get-JiraUrl {
    $config = Get-Config
    if ($config -and $config.jira_url) {
        return $config.jira_url
    }

    $jiraUrl = Read-Host "Enter your Jira URL (e.g., https://your-domain.atlassian.net)"
    $config = @{ jira_url = $jiraUrl }
    Save-Config $config

    return $jiraUrl
}

function Check-GitRepo {
    if (-not (Test-Path .git)) {
        Write-Host "Error: Not in a git repository." -ForegroundColor Red
        exit 1
    }
}

function Check-And-Set-Origin {
    $origin = git remote get-url origin 2>$null
    if (-not $origin) {
        Write-Host "Origin not set. Setting origin to https://github.com/LogSentry/LogSentry-Insights.git" -ForegroundColor Yellow
        git remote add origin https://github.com/LogSentry/LogSentry-Insights.git
    }
    elseif ($origin -ne "https://github.com/LogSentry/LogSentry-Insights.git") {
        Write-Host "Origin is not set to https://github.com/LogSentry/LogSentry-Insights.git. Updating..." -ForegroundColor Yellow
        git remote set-url origin https://github.com/LogSentry/LogSentry-Insights.git
    }
}

function Fetch-And-Select-Task {
    Write-Host "Fetching your assigned Jira tasks..." -ForegroundColor Cyan
    $jiraUrl = Get-JiraUrl
    $jiraToken = Get-JiraToken
    $tasks = Invoke-RestMethod -Uri "$jiraUrl/rest/api/2/search?jql=assignee=currentUser()+AND+status!=Done" -Headers @{Authorization = "Bearer $jiraToken"} -Method Get
    
    if ($tasks.issues.Count -eq 0) {
        Write-Host "No tasks found assigned to you." -ForegroundColor Red
        exit 1
    }

    Write-Host "Your assigned tasks:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $tasks.issues.Count; $i++) {
        Write-Host "$($i+1)) $($tasks.issues[$i].key): $($tasks.issues[$i].fields.summary)" -ForegroundColor Yellow
    }

    $taskNumber = Read-Host "Select a task number"
    $selectedTask = $tasks.issues[$taskNumber - 1]
    $jiraCode = $selectedTask.key
    Write-Host "Selected task: $($jiraCode): $($selectedTask.fields.summary)" -ForegroundColor Green
    return $jiraCode, $selectedTask.fields.summary
}

function Create-And-Switch-Branch($jiraCode, $summary) {
    $branchName = "$($jiraCode.ToLower())-$($summary -replace '[^\w\-]', '-' -replace '-+', '-' -replace '^-|-$')"
    
    git checkout main
    git pull origin main --rebase
    git checkout -b $branchName
    git push -u origin $branchName
    
    Write-Host "Created and switched to branch: $branchName" -ForegroundColor Green
}

function Extract-JiraCode {
    $branchName = git rev-parse --abbrev-ref HEAD
    $jiraCode = [regex]::Match($branchName, '[A-Z]+-[0-9]+').Value
    
    if (-not $jiraCode) {
        Write-Host "No Jira task code found in branch name." -ForegroundColor Yellow
        $continueWithoutCode = Read-Host "Do you want to continue without a Jira task code? (y/n)"
        if ($continueWithoutCode -ne "y") {
            exit 1
        }
    }
    
    return $jiraCode
}

function Update-JiraStatus($jiraCode, $newStatus) {
    $jiraUrl = Get-JiraUrl
    $jiraToken = Get-JiraToken
    
    $body = @{
        transition = @{
            name = $newStatus
        }
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "$jiraUrl/rest/api/2/issue/$jiraCode/transitions" -Headers @{Authorization = "Bearer $jiraToken"} -Method Post -Body $body -ContentType "application/json"
}

function Get-JiraStatus($jiraCode) {
    $jiraUrl = Get-JiraUrl
    $jiraToken = Get-JiraToken
    
    $response = Invoke-RestMethod -Uri "$jiraUrl/rest/api/2/issue/$jiraCode" -Headers @{Authorization = "Bearer $jiraToken"} -Method Get
    return $response.fields.status.name
}

function Create-PullRequest {
    $branchName = git rev-parse --abbrev-ref HEAD
    $repoName = "LogSentry/LogSentry-Insights"
    $githubToken = Get-GithubToken
    
    $body = @{
        title = "Pull request for $branchName"
        head = $branchName
        base = "main"
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "https://api.github.com/repos/$repoName/pulls" -Headers @{Authorization = "token $githubToken"} -Method Post -Body $body -ContentType "application/json"
}

function Start-NewTask {
    Check-GitRepo
    Show-ProgressBar -PercentComplete 10 -Status "Checking Git repository"
    
    Check-And-Set-Origin
    Show-ProgressBar -PercentComplete 20 -Status "Setting Git origin"
    
    $jiraCode, $summary = Fetch-And-Select-Task
    Show-ProgressBar -PercentComplete 60 -Status "Fetched Jira task"
    
    Create-And-Switch-Branch $jiraCode $summary
    Show-ProgressBar -PercentComplete 100 -Status "Created and switched to new branch"
    
    Write-Host "`nNew task started successfully!" -ForegroundColor Green
}

function Complete-Task {
    Check-GitRepo
    Show-ProgressBar -PercentComplete 10 -Status "Checking Git repository"
    
    Check-And-Set-Origin
    Show-ProgressBar -PercentComplete 20 -Status "Setting Git origin"

    if (git status --porcelain) {
        Write-Host "`nUnstaged changes detected. Staging all changes..." -ForegroundColor Yellow
        git add .
    }
    Show-ProgressBar -PercentComplete 30 -Status "Staged changes"

    $jiraCode = Extract-JiraCode
    Show-ProgressBar -PercentComplete 40 -Status "Extracted Jira code"

    if ($jiraCode) {
        $commitMessage = Read-Host "`nEnter commit message (Jira code $jiraCode will be prepended)"
        $fullCommitMessage = "[$jiraCode] $commitMessage"
    }
    else {
        $commitMessage = Read-Host "`nEnter commit message"
        $fullCommitMessage = $commitMessage
    }

    git commit -m $fullCommitMessage
    Show-ProgressBar -PercentComplete 50 -Status "Committed changes"

    git config push.default current

    Write-Host "`nPushing to GitHub..." -ForegroundColor Cyan
    git push origin
    Show-ProgressBar -PercentComplete 60 -Status "Pushed to GitHub"

    Write-Host "`nCreating pull request..." -ForegroundColor Cyan
    Create-PullRequest
    Show-ProgressBar -PercentComplete 70 -Status "Created pull request"

    if ($jiraCode) {
        $currentStatus = Get-JiraStatus $jiraCode
        if ($currentStatus -eq "To Do") {
            Write-Host "`nUpdating Jira issue status to In Progress..." -ForegroundColor Yellow
            Update-JiraStatus $jiraCode "In Progress"
        }
        Show-ProgressBar -PercentComplete 80 -Status "Updated Jira status"
        
        $markDone = Read-Host "`nDo you want to mark the Jira issue as Done? (y/n)"
        if ($markDone -eq "y") {
            Write-Host "Updating Jira issue status to Done..." -ForegroundColor Green
            Update-JiraStatus $jiraCode "Done"
        }
        Show-ProgressBar -PercentComplete 90 -Status "Finalized Jira status"
    }

    Show-ProgressBar -PercentComplete 100 -Status "Task completed"
    Write-Host "`nTask completed successfully!" -ForegroundColor Green
}

function Setup-GitWorkflow {
    Write-Host "Starting Git Workflow Setup..." -ForegroundColor Cyan

    Show-ProgressBar -PercentComplete 10 -Status "Creating scripts directory"
    if (-not (Test-Path $scriptsDir)) {
        New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
    }

    Show-ProgressBar -PercentComplete 20 -Status "Creating git-get.cmd"
    @"
@echo off
powershell.exe -ExecutionPolicy Bypass -File "$scriptsDir\git-workflow.ps1" get %*
"@ | Set-Content -Path "$scriptsDir\git-get.cmd"

    Show-ProgressBar -PercentComplete 30 -Status "Creating git-done.cmd"
    @"
@echo off
powershell.exe -ExecutionPolicy Bypass -File "$scriptsDir\git-workflow.ps1" done %*
"@ | Set-Content -Path "$scriptsDir\git-done.cmd"

    Show-ProgressBar -PercentComplete 40 -Status "Updating PATH"
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$scriptsDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$scriptsDir", "User")
    }

    Show-ProgressBar -PercentComplete 60 -Status "Configuring Git aliases"
    git config --global alias.get "!git-get.cmd"
    git config --global alias.done "!git-done.cmd"

    Show-ProgressBar -PercentComplete 80 -Status "Copying script to scripts directory"
    Copy-Item $PSCommandPath $scriptsDir -Force

    Show-ProgressBar -PercentComplete 100 -Status "Setup completed"

    Write-Host "`n`nSetup complete. You can now use 'git get' and 'git done' commands." -ForegroundColor Green
    Write-Host "Please restart your command prompt for the PATH changes to take effect." -ForegroundColor Yellow
}
# Main execution
Write-Host "Entering main execution" -ForegroundColor Cyan

if ($args.Count -eq 0) {
    Write-Host "No arguments provided. Usage: git-workflow.ps1 [get|done|setup]" -ForegroundColor Yellow
    Write-Host "  get   - Start a new task" -ForegroundColor Cyan
    Write-Host "  done  - Complete the current task" -ForegroundColor Cyan
    Write-Host "  setup - Set up the git workflow" -ForegroundColor Cyan
}
elseif ($args[0] -eq "get") {
    Write-Host "Starting new task..." -ForegroundColor Green
    Start-NewTask
}
elseif ($args[0] -eq "done") {
    Write-Host "Completing task..." -ForegroundColor Green
    Complete-Task
}
elseif ($args[0] -eq "setup") {
    Write-Host "Setting up Git workflow..." -ForegroundColor Green
    Setup-GitWorkflow
}
else {
    Write-Host "Invalid argument. Usage: git-workflow.ps1 [get|done|setup]" -ForegroundColor Red
    Write-Host "  get   - Start a new task" -ForegroundColor Cyan
    Write-Host "  done  - Complete the current task" -ForegroundColor Cyan
    Write-Host "  setup - Set up the git workflow" -ForegroundColor Cyan
}

Write-Host "Script execution completed" -ForegroundColor Cyan