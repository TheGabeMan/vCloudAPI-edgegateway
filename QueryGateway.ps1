function Get-AccessToken{
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$vCloudURL,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$PairBase64,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$HeaderAccept        
    )

    $AuthBasicHeaders = @{ Authorization = "Basic $PairBase64"; Accept = $HeaderAccept}
    $uri = "$($vCloudURL)/sessions"
    $response = Invoke-WebRequest -Method Post -Headers $AuthBasicHeaders -Uri $uri
    $AccessToken =  $response.headers['X-VMWARE-VCLOUD-ACCESS-TOKEN']
    return $AccessToken
}

function Get-EdgeGateways{
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$vCloudURL,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$AccessToken,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$HeaderAccept        
    ) 


    $headers = @{ Authorization = "Bearer $AccessToken"; Accept = $HeaderAccept}
    $uri = "$($vCloudURL)/query?type=edgeGateway"
    $response = Invoke-RestMethod -Method GET -uri $uri -Headers $headers 
    Return $response
}

function Get-EdgeGateway{
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$GatewayHREF,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$AccessToken,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$HeaderAccept        
    )
    
    $headers = @{ Authorization = "Bearer $AccessToken"; Accept = $HeaderAccept}
    $response = Invoke-RestMethod -Method GET -uri $GatewayHREF -Headers $headers 
    Return $response

}

function Get-EdgeGatewaysFirewallRules{
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$EdgeGateway
    ) 

    $FWRules = $EdgeGateway.configuration.edgeGatewayServiceConfiguration.networkService | where-object{ $_._type -eq "FirewallServiceType"}
    $FirewallReport = @()
    Foreach( $FWrule in $FWrules.FirewallRule)
    {
        $row = "" | Select-object id, isEnabled, otherAttributes, description, Policy, protocols, icmpSubtype, DestinationPortRange, DestinationIP, destinationvm, sourceip,sourceportrange, sourcevm, enableLogging
        $row.id = $FWRule.ID
        $row.isEnabled = $FWRule.isEnabled
        $row.otherAttributes = $FWRule.otherAttributes
        $row.description = $FWRule.description
        $row.Policy = $FWRule.Policy
        $row.protocols = $FWRule.protocols
        $row.icmpSubtype = $FWRule.icmpSubtype
        $row.DestinationPortRange = $FWRule.DestinationPortRange
        $row.DestinationIP = $FWRule.DestinationIP
        $row.destinationvm = $FWRule.destinationvm
        $row.sourceip = $FWRule.sourceip
        $row.sourceportrange = $FWRule.sourceportrange
        $row.sourcevm = $FWRule.sourcevm
        $row.enableLogging = $FWRule.enableLogging
        $FirewallReport += $row
    }


    Return $FirewallReport
}

function Get-EdgeGatewaysNATRules{
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$EdgeGateway
    ) 

    $NATRules = $EdgeGateway.configuration.edgeGatewayServiceConfiguration.networkService | where-object{ $_._type -eq "NatServiceType"}
    $NATReport = @()
    Foreach( $NATrule in $NATRules.natRULE)
    {
        $row = "" | Select-object otherAttributes, description, ruleType, isEnabled, id, gatewayNatRule, oneToOneBasicRule, oneToOneVmRule, portForwardingRule, vmRule
        $row.otherAttributes = $NATRule.otherAttributes
        $row.description = $NATRule.description
        $row.ruleType = $NATRule.ruleType
        $row.isEnabled = $NATRule.isEnabled
        $row.id = $NATRule.ID
        $row.gatewayNatRule = $NATRule.gatewayNatRule
        $row.oneToOneBasicRule = $NATRule.oneToOneBasicRule
        $row.oneToOneVmRule = $NATRule.oneToOneVmRule
        $row.portForwardingRule = $NATRule.portForwardingRule
        $row.vmRule = $NATRule.vmRule
        $NATReport += $row
    }
    Return $NATReport
}

function Get-EdgeGatewaysNATRulesDetails{
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$reportrules
    ) 
    $report = @()
    foreach( $rule in $reportrules)
    {
        foreach( $gatewayNatRule in $rule.gatewayNatRule)
        {
            $row = "" | Select-Object description, ruleType, isEnabled, id, originalIP, originalPort, translatedIP, translatedPort, protocol, icmpSubtype, networkname
            $row.description = $rule.description
            $row.ruleType = $rule.ruleType
            $row.isEnabled = $rule.isEnabled
            $row.id = $rule.id
            
            $row.originalIP = $gatewayNatRule.originalIP
            $row.originalPort = $gatewayNatRule.originalPort
            $row.translatedIP = $gatewayNatRule.translatedIP
            $row.translatedPort = $gatewayNatRule.translatedPort
            $row.protocol = $gatewayNatRule.protocol
            $row.icmpSubtype = $gatewayNatRule.icmpSubtype
            $row.networkname = $gatewayNatRule.interface.name
            $report += $row
        }
    }
    return $report
}

$Username = read-host "Username (user@org or admin@system): "
$passwd = read-host "Password: "
$vCloudURL = read-host "What is the API url for your vCloud? (e.g. https://cloud.domain.com/api"

$Pair = "$($UserName):$($Passwd)"
$Bytes = [System.Text.Encoding]::ASCII.GetBytes($Pair)
$PairBase64 = [System.Convert]::ToBase64String($Bytes)

$HeaderAccept = "application/*+json;version=36.2"
$AccessToken = Get-AccessToken -vCloudURL $vCloudURL -PairBase64 $PairBase64 -HeaderAccept $HeaderAccept
$EdgeGateways = Get-EdgeGateways -vCloudURL $vCloudURL -AccessToken $AccessToken -HeaderAccept $HeaderAccept

$SelectedGateway = $EdgeGateways.record.name | Out-GridView -Title "Select the EdgeGateway" -PassThru
$GatewayToGet = $EdgeGateways.record | where-object{ $_.name -eq $SelectedGateway }
$EdgeGateway = Get-EdgeGateway -GatewayHREF $($GatewayToGet.href) -AccessToken $AccessToken -HeaderAccept $HeaderAccept

$FirewallReport = Get-EdgeGatewaysFirewallRules -EdgeGateway $EdgeGateway
$NATReport = Get-EdgeGatewaysNATRules -EdgeGateway $EdgeGateway

$NATDetails = Get-EdgeGatewaysNATRulesDetails -report $NATReport

## Export
$timestamp = get-date -uformat "%Y%m%d%H%M"
$ExportNAT = "h:\" + $($($gatewaytoget.name) -replace ' ', '') + "_NATRules_" + $timestamp + ".csv"
$NATDetails | Export-Csv -Path $ExportNAT -NoTypeInformation

$ExportFW = "h:\" + $($($gatewaytoget.name) -replace ' ', '') + "_FWRules_" + $timestamp + ".csv"
$FirewallReport | Export-Csv -Path $ExportFW -NoTypeInformation



## Todo list:
##  loadbalancer
## ($webresult.configuration.edgeGatewayServiceConfiguration.networkService | where-object{ $_._type -eq "LoadBalancerServiceType"})
## StaticRoutingServiceType
## ($webresult.configuration.edgeGatewayServiceConfiguration.networkService | where-object{ $_._type -eq "StaticRoutingServiceType"})
## GatewayIpsecVpnServiceType
## ($webresult.configuration.edgeGatewayServiceConfiguration.networkService | where-object{ $_._type -eq "GatewayIpsecVpnServiceType"})
