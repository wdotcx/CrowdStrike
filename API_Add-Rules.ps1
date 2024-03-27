#
# 'API_Add-Rule.ps1' based from https://github.com/CrowdStrike/psfalcon/wiki/Edit-FalconFirewallGroup
#
# Add CrowdStrike firewall rules from csv "Dir,Version,Active,ICMP4,EmbedCtxt,Action,LA4,RPort,Protocol,Profile,RMAuth,Svc,Desc,Security,RA4,LPort,Name,App" (not all fields used)
# csv fields from exported Windows Firewall Group Policy, as xml then parsed to csv (WindowsFirewall_xml2csv.py)
#
Import-Module PSFalcon

#
# Variables
#
$ClientId = ''
$ClientSecret = ''
$FalconFirewallGroup = ''
$csvData = Import-Csv -Path "example.csv"

#
# Main
#
Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret

[Array]::Reverse($csvData)
$lineNumber = $csvData.Count + 1    # Offset for csv header

foreach ($line in $csvData) {

    if ($line.Dir -eq 'In') { $line.Dir = 'IN' } elseif ($line.Dir -eq 'Out') { $line.Dir = 'OUT' }
    else { Write-Host "Failed at line $lineNumber. Direction not found. $line"; continue }

    if ($line.Active -eq 'TRUE') { $line.Active = $true } elseif ($line.Active -eq 'FALSE') { $line.Active = $false }
    else { Write-Host "Failed at line $lineNumber. Active not found. $line"; continue }

    if ($line.Action -eq 'Allow') { $line.Action = 'ALLOW' } elseif ($line.Action -eq 'Block') { $line.Action = 'DENY' }
    else { Write-Host "Failed at line $lineNumber. Action not found. $line"; continue }

    # Handle 'RA4' column for remote_address
    if ([string]::IsNullOrWhiteSpace($line.RA4)) {
        $remoteAddress = @(
            @{ address = '*'; netmask = 0 }    # ANY
        )
    } else {
        $ipAddresses = $line.RA4 -split ';' | ForEach-Object { $_.Trim() }
        $remoteAddress = @()
        foreach ($ip in $ipAddresses) {
            if ($ip -match '/') {   # If the address has a CIDR block e.g. "10.0.1.0/24"
                $cidrParts = $ip -split '/'
                $remoteAddress += @{ address = $cidrParts[0]; netmask = [int]$cidrParts[1] }
            } else {    # If the address does not have CIDR block
                $remoteAddress += @{ address = $ip; netmask = 0 }
            }
        }
    }

    # Handle 'LA4' column for local_address
    if ([string]::IsNullOrWhiteSpace($line.LA4)) {
        $localAddress = @(
            @{ address = '*'; netmask = 0 }    # ANY
        )
    } else {
        $ipAddresses = $line.LA4 -split ';' | ForEach-Object { $_.Trim() }
        $localAddress = @()
        foreach ($ip in $ipAddresses) {
            if ($ip -match '/') {    # If the address has a CIDR block e.g. "10.0.1.0/24"
                $cidrParts = $ip -split '/'
                $localAddress += @{ address = $cidrParts[0]; netmask = [int]$cidrParts[1] }
            } else {    # If the address does not have CIDR block
                $localAddress += @{ address = $ip; netmask = 0 }
            }
        }
    }

    $localPort = @()
    $remotePort = @()

    if ([string]::IsNullOrWhiteSpace($line.Protocol)) {    # Ports not allowed without a specific Protocol
        $line.Protocol = '*'    # ANY
    } else {

        # Handle 'RPort' column for remote_port
        if (![string]::IsNullOrWhiteSpace($line.RPort)) {
            $rPorts = $line.RPort -split ',' | ForEach-Object { $_.Trim() }
            foreach ($rport in $rPorts) {
                if ($rport -match '-') {    # If port range e.g. "135, 49152-65535"
                    $portRange = $rport -split '-'
                    $remotePort += @{ start = [int]$portRange[0]; end = [int]$portRange[1] }
                } else {
                    $remotePort += @{ start = [int]$rport; end = 0 }    # [int] Remove quotes around port numbers
                }
            }
        }

        # Handle 'LPort' column for local_port
        if (![string]::IsNullOrWhiteSpace($line.LPort)) {
            $lPorts = $line.LPort -split ',' | ForEach-Object { $_.Trim() }
            foreach ($lport in $lPorts) {
                if ($lport -match '-') {    # If port range e.g. "135, 49152-65535"
                    $portRange = $lport -split '-'
                    $localPort += @{ start = [int]$portRange[0]; end = [int]$portRange[1] }
                } else {
                    $localPort += @{ start = [int]$lport; end = 0 }    # [int] Remove quotes around port numbers
                }
            }
        }
    }

    if (![string]::IsNullOrWhiteSpace($line.Svc)) {
        $service = @{ name='service_name'; type='string'; value=$line.Svc }
    } else {
        $service = @()
    }

    $fieldsTable = @(
        @{ name = 'network_location'; type = 'set'; values = @( 'ANY' ) }
        @{ name = 'image_name'; type = 'windows_path'; value = $line.App }
    )

    if ($service.Count -gt 0) { $fieldsTable += $service }    # service_name only requred if Svc in csv

    $valueTable = @{
        temp_id = '1'
        name = $line.Name
        description = ''
        platform_ids = @('0')
        enabled = $line.Active
        action = $line.Action
        direction = $line.Dir
        address_family = 'IP4'
        protocol = $line.Protocol
        fields = $fieldsTable
        local_address = $localAddress
        remote_address = $remoteAddress
    }

    if ($localPort.Count -gt 0) { $valueTable['local_port'] = $localPort }    # local_port only requred if there are LPorts in csv
    if ($remotePort.Count -gt 0) { $valueTable['remote_port'] = $remotePort }    # remote_port only requred if there are RPorts in csv

    $DiffOperation = @(
        @{
            op = 'add'
            path = '/rules/0'
            value = $valueTable
        }
    )

    $Group = Get-FalconFirewallGroup -Id $FalconFirewallGroup
    $Rule = Get-FalconFirewallRule -Id $Group.rule_ids
    $RuleId = @('1') + $Group.rule_ids
    $RuleVersion = @('0') + $Rule.version

    #$DiffOperation | ConvertTo-Json -Depth 10 | Write-Output

    try {
        Write-Host "Processing line $lineNumber."
        Edit-FalconFirewallGroup -Id $Group.id -DiffOperation $DiffOperation -RuleId $RuleId -RuleVersion $RuleVersion -ErrorAction Continue
    }
    catch {
        Write-Host "An error occurred at line $lineNumber. $_"
    }

    $lineNumber--

}
