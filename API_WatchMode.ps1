#
# 'API_WatchMode.ps1' Quickly enable or disable CrowdStike Watch Mode on firewall rules within a rule-group.
#
Import-Module PSFalcon

#
# Variables
#
$ClientId = ''
$ClientSecret = ''
$FalconFirewallGroup = ''

$WatchMode = '1'    # 1 - Enabled or 0 - Disabled
$WatchModeRuleId = @(1, 4, 5, '4-10', 17, 34)    # CrowdStrike rule number or range e.g. (1, 4, 5, '4-10', 17, 34)

#
# Main
#
Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret

$rangeArray = @()

foreach ($i in $WatchModeRuleId) {
    if ($i -match "^(\d+)-(\d+)$") {    # Match WatchModeRuleId values that are ranges e.g. 4-10
        $rangeRuleIdStart = [int]$matches[1]
        $rangeRuleIdEnd = [int]$matches[2]
        $rangeArray += $rangeRuleIdStart..$rangeRuleIdEnd
    } else {
        $rangeArray += [int]$i
    }
}

$rangeArray = $rangeArray | Sort-Object -Unique    # Remove WatchModeRuleId duplicate values from rangeArray

foreach ($i in $rangeArray) {
    $Index = $i - 1

    $DiffOperation = @(
        @{
            "op" = "replace"
            "path" = "/rules/$Index/monitor"
            "value" = @{
                "count" = $WatchMode
                "period_ms" = "86400000"
            }
        }
    )
    $Group = Get-FalconFirewallGroup -Id $FalconFirewallGroup
    $Rule = Get-FalconFirewallRule -Id $Group.rule_ids
    $RuleId = $Group.rule_ids
    $RuleVersion = $Rule.version

    #$DiffOperation | ConvertTo-Json -Depth 10 | Write-Output

    try {
        Edit-FalconFirewallGroup -Id $Group.id -DiffOperation $DiffOperation -RuleId $RuleId -RuleVersion $RuleVersion
    }
    catch {
        Write-Host "DEBUG: An error occurred"
    }

}
