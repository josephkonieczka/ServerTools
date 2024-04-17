<#
Possible Service Status States
https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontroller.status?view=dotnet-plat-ext-7.0


$WindowsServiceStates = [enum]::GetNames([System.ServiceProcess.ServiceControllerStatus])

$WindowsServiceStates

Running
Stopped
StartPending
StopPending
ContinuePending
PausePending
Paused

https://datatracker.ietf.org/doc/html/rfc9293#name-state-machine-overview

https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2022-ps
https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.tcpstate
$NetTCPConnectionStates = [enum]::GetNames([Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.State])

$NetTCPConnectionStates

Closed
Listen
SynSent
SynReceived
Established
FinWait1
FinWait2
CloseWait
Closing
LastAck
TimeWait
DeleteTCB
Bound


#>

function Set-AppDTCPPortStatesTable
{
    $NetTCPConnectionStates = @{
        'Listen'      = 1
        'Bound'       = 2
        'Established' = 3
        'FinWait1'    = 4
        'FinWait2'    = 5
        'LastAck'     = 6  
        'SynReceived' = 7
        'SynSent'     = 8
        'TimeWait'    = 9
        'Closing'     = 10
        'CloseWait'   = 11
        'Closed'      = 12
        'DeleteTCB'   = 13  
        'UNKNOWN'     = 14
    }
    $NetTCPConnectionStates
}

function Get-AppDTCPPortStates
{
    param(
        $monitoredPorts,
        $currentTCPConnections,
        $statesTable
    )
    $metricStringArray = @()
    $monitoredPortsStatusHash = @{}

    foreach ($port in $monitoredPorts)
    {
        $portName = $port.portName
        $portCount = 0
        $monitoredPortsStatusHash.Add($portName, $portCount)
        #$connectionCount 
        $matchedPorts = $currentTCPConnections `
        | Where-Object {
            $_.LocalAddress -like "$($port.LocalAddress)" `
                -and $_.LocalPort -Like "$($port.LocalPort)" `
                -and $_.RemoteAddress -Like "$($port.RemoteAddress)" `
                -and $_.RemotePort -Like "$($port.RemotePort)"
        }
        if ($matchedPorts) 
        {
            $uniqueStates = $matchedPorts.State | Select-Object -Unique
            foreach ($state in $uniqueStates)
            {            
                $objectsinState = $matchedPorts | Where-Object { $_.State -eq $state }
                <#
                Windows PowerShell 5.x seems to have a bug when only a single entry is returned for a state.
                When it is only 1, the .Count property is empty. Otherwise, it is populated.
                Workaround here is to manually set state to 1 in that event.
                #>
                $numberinState = $objectsinState.Count
                if (!$numberinState -and $objectsinState)
                {
                    $numberinState = 1
                }
                $metricString = "name=Custom Metrics|Server Tools|portState|$($portName)|$($state),value=$($numberinState),aggregator=OBSERVATION"
                $metricStringArray += $metricString
                $portCount += $numberinState     
            }
            $monitoredPortsStatusHash[$portName] = $portCount
        }
        $metricString = "name=Custom Metrics|Server Tools|portCount|$($portName)|portCount,value=$($monitoredPortsStatusHash[$portName]),aggregator=OBSERVATION"
        $metricStringArray += $metricString
    }
    Write-Output $metricStringArray
}

function Set-AppDWindowsServiceStatesTable
{
    $WindowsServiceStates = @{
        'Running'         = 0
        'Stopped'         = 1
        'StartPending'    = 2
        'StopPending'     = 3
        'ContinuePending' = 4
        'PausePending'    = 5
        'Paused'          = 6
        'NOTFOUND'        = 7
    }
    $WindowsServiceStates
}

function Get-AppWindowsServiceStates
{
    param(
        $monitoredServices,
        $statesTable
    )
    foreach ($service in $monitoredServices)
    {        
        $serviceName = $service.ServiceName
        $serviceInfo = Get-Service -Name $service.ServiceName -ErrorAction SilentlyContinue
        if ($serviceInfo)
        {
            $serviceStatus = $serviceInfo.Status
            $stateValue = $statesTable["$serviceStatus"]
        }
        else
        {
            $stateValue = $statesTable['NOTFOUND']
            <# Action when all if and elseif conditions are false #>
        }
        $service `
        | Add-Member -MemberType NoteProperty -Name 'stateValue' -Value $stateValue 

        $metricString = "name=Custom Metrics|Server Tools|serviceState|$($serviceName)|State,value=$($stateValue),aggregator=OBSERVATION"
        $service `
        | Add-Member -MemberType NoteProperty -Name 'metricString' -Value $metricString
        Write-Output $service
    }
}

$monitoredservicesFile = "$PSScriptRoot\monitoredServices.csv"
$monitoredPortsFile = "$PSScriptRoot\monitoredPorts.csv"

$WindowsServiceStatesTable = Set-AppDWindowsServiceStatesTable
$monitoredServices = Import-Csv $monitoredServicesFile
$WindowsServiceStates = Get-AppWindowsServiceStates -monitoredServices $monitoredServices -statesTable $WindowsServiceStatesTable
$WindowsServiceStates.metricString

$TCPPortStatesTable = Set-AppDTCPPortStatesTable
$monitoredPorts = Import-Csv $monitoredPortsFile
$currentTCPConnections = Get-NetTCPConnection
$TCPPortStates = Get-AppDTCPPortStates -monitoredPorts $monitoredPorts -currentTCPConnections $currentTCPConnections -statesTable $TCPPortStatesTable
$TCPPortStates

