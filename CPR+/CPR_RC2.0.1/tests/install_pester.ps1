# Install Pester (if not already installed)
Install-Module -Name Pester -Force -SkipPublisherCheck

# Check version (you want 5.x)
Get-Module Pester -ListAvailable

# If you have old version, update it
Update-Module Pester

#WhiteWalker/
#├── bump_ISE.ps1              # Your main script
#├── WhiteWalker.Tests.ps1     # The test file above
#└── TestResults/              # Pester will create this for reports

#
## Basic test run
# Invoke-Pester .\WhiteWalker.Tests.ps1

# With detailed output
# Invoke-Pester .\WhiteWalker.Tests.ps1 -Output Detailed

# Generate coverage report
# Invoke-Pester .\WhiteWalker.Tests.ps1 -CodeCoverage .\bump_ISE.ps1

# Run specific test context
# Invoke-Pester .\WhiteWalker.Tests.ps1 -Tag "VPN"
