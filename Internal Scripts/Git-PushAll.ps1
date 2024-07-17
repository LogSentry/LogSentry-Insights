Add-Type -AssemblyName System.Security

# Function to write formatted output
function Write-Step {
    param (
        [string]$Message
    )
    Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}

# Function to securely save the token
function Save-SecureToken {
    param (
        [string]$Token
    )
    $secureToken = ConvertTo-SecureString -String $Token -AsPlainText -Force
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        [System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $encrypted | Set-Content "$env:USERPROFILE\.github_token" -Encoding Byte
}

# Function to retrieve the secure token
function Get-SecureToken {
    if (Test-Path "$env:USERPROFILE\.github_token") {
        $encrypted = Get-Content "$env:USERPROFILE\.github_token" -Encoding Byte
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    return $null
}

# Function to create or update pull request
function Create-Or-Update-PullRequest {
    param (
        [string]$Token,
        [string]$RepoOwner,
        [string]$RepoName,
        [string]$Branch,
        [string]$Title
    )

    $headers = @{
        Authorization = "token $Token"
        Accept = "application/vnd.github.v3+json"
    }

    $body = @{
        title = $Title
        head = $Branch
        base = "main"
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/pulls" -Method Post -Headers $headers -Body $body -ContentType "application/json"
        Write-Host "Pull request created successfully:" -ForegroundColor Green
        Write-Host "Title: $($response.title)" -ForegroundColor Yellow
        Write-Host "URL: $($response.html_url)" -ForegroundColor Yellow
        Write-Host "Status: $($response.state)" -ForegroundColor Yellow
    } catch {
        if ($_.Exception.Response.StatusCode -eq 422) {
            Write-Host "Pull request already exists. Updating..." -ForegroundColor Yellow
            $existingPRs = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/pulls?head=$RepoOwner`:$Branch&state=open" -Method Get -Headers $headers
            if ($existingPRs.Count -gt 0) {
                $prNumber = $existingPRs[0].number
                $updateBody = @{
                    title = $Title
                } | ConvertTo-Json
                $updateResponse = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/pulls/$prNumber" -Method Patch -Headers $headers -Body $updateBody -ContentType "application/json"
                Write-Host "Pull request updated successfully:" -ForegroundColor Green
                Write-Host "Title: $($updateResponse.title)" -ForegroundColor Yellow
                Write-Host "URL: $($updateResponse.html_url)" -ForegroundColor Yellow
                Write-Host "Status: $($updateResponse.state)" -ForegroundColor Yellow
            } else {
                Write-Host "Error: Could not find existing pull request to update." -ForegroundColor Red
            }
        } else {
            Write-Host "Error creating/updating pull request:" -ForegroundColor Red
            Write-Host $_.Exception.Message
            if ($_.Exception.Response) {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                Write-Host $responseBody
            }
        }
    }
}

# Start of script
Write-Step "Starting Git PushAll script"

# Get the current branch name
$branch = git rev-parse --abbrev-ref HEAD
Write-Host "Current branch: $branch" -ForegroundColor Yellow

# Get the last commit message
$commit_msg = git log -1 --pretty=%s
Write-Host "Last commit message: $commit_msg" -ForegroundColor Yellow

# Push to Bitbucket
Write-Step "Pushing to Bitbucket"
$bitbucketResult = git push https://kanishkthamman@bitbucket.org/logicinsights/logicinsights.git HEAD:$branch
if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully pushed to Bitbucket" -ForegroundColor Green
} else {
    Write-Host "Failed to push to Bitbucket" -ForegroundColor Red
    Write-Host $bitbucketResult
}

# Push to GitHub
Write-Step "Pushing to GitHub"
$githubResult = git push https://github.com/LogSentry/LogSentry-Insights.git HEAD:$branch
if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully pushed to GitHub" -ForegroundColor Green
} else {
    Write-Host "Failed to push to GitHub" -ForegroundColor Red
    Write-Host $githubResult
}

# Create or update pull request on GitHub
Write-Step "Creating or updating pull request on GitHub"

# Check if the token is stored securely
$token = Get-SecureToken
if (-not $token) {
    $token = Read-Host "Enter your GitHub Personal Access Token"
    Save-SecureToken -Token $token
    Write-Host "GitHub token saved securely" -ForegroundColor Green
}

Create-Or-Update-PullRequest -Token $token -RepoOwner "LogSentry" -RepoName "LogSentry-Insights" -Branch $branch -Title $commit_msg

Write-Step "Git PushAll script completed"