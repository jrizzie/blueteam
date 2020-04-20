#---------------------------------------------------
# Lab 3 
#
function Survey-Accounts {
	
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[string[]]
		$ComputerName,

		[pscredential]
		$Credential
	)
	Begin {
		If ( !$Credential) {$Credential = Get-Credential}
	} # End of Begin Block
	Process {
		Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
			Get-WmiObject win32_UserAccount | Select-Object AccountType,Name,LocalAccount,Domain,SID
		} # End of Script Block
	} # End of Process Block
	

} # End of function block

#---------------------------------------------------
# Lab 4 
#
function Survey-Services {
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[string[]]
		$ComputerName,

		[pscredential]
		$Credential
	)
	Begin {
		If ( !$Credential) {$Credential = Get-Credential}
	} # End of Begin Block
	Process {
		Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
			Get-WmiObject win32_Service | Select-Object Name,PathName,State,StartMode,StartName
		} # End of Script Block
	} # End of Process Block

}
#---------------------------------------------------
# Lab 5 
#
function Survey-FileHash{
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[string[]]
		$ComputerName,

		[pscredential]
		$Credential,

		[Parameter(Mandatory=$true)]
		[string]
		$Path
	)
	Begin {
		If ( !$Credential) {$Credential = Get-Credential}
	} # End of Begin Block
	Process {
		Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
			Get-ChildItem -Path $using:Path |
				Where-Object { $_.extension } |
				Select-Object name,@{n="hash";e={(certutil.exe -hashfile $_.fullname SHA256)[1] -replace " ",""}}
		} # End of Script Block
	} # End of Process Block
}
#
#---------------------------------------------------
# Lab 6
#
function Survey-Processes{
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[string[]]
		$ComputerName,

		[pscredential]
		$Credential
	)
	Begin {
		If ( !$Credential) {$Credential = Get-Credential}
	} # End of Begin Block
	Process {
		Invoke-Command -ComputerName $ComputerName -Credential $Credential {
			Get-WmiObject win32_process |
			Select-Object csname,Name,ProcessID,Path,CommandLine,
				@{n="hash";e={ if($_.Path) {(certutil.exe -hashfile $_.Path SHA256)[1] -replace " ","" } else { $null } } },
				@{n="user";e={$_.GetOwner().Domain + "\" + $_.GetOwner().User}}
		} # End of Script Block
	} # End of Process Block
}
#
#---------------------------------------------------
# Lab 7

function Survey-Firewall{

	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[string[]]
		$ComputerName,

		[pscredential]
		$creds
	)
	Begin {
		If ( !$creds) {$creds = Get-Credential}
	} # End of Begin Block
	Process {
		Invoke-Command -ComputerName $ComputerName -Credential $creds -ScriptBlock {
#124 - Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
# - test icm -cn 192.168.80.102 -cr $creds {hostname}
			$rules = Get-NetFirewallRule | Where-Object { $_.Enabled }
			$portfilter = Get-NetFirewallPortFilter
			$addressfilter = Get-NetFirewallAddressFilter 
			foreach ($rule in $rules) {
				$ruleport = $portfilter | Where-Object { $_.InstanceID -eq $rule.InstanceID }
				$ruleaddress = $addressfilter | Where-Object { $_.InstanceID -eq $rule.InstanceID }
				$data = @{ InstanceID = $rule.InstanceID.ToString()
					Direction = $rule.Direction.ToString()
					Action = $rule.Action.ToString()
					LocalAddress = $ruleaddress.LocalAddress -join ","
					RemoteAddress = $ruleaddress.RemoteAddress -join ","
					Protocol = $ruleport.Protocol.ToString()
					LocalPort = $ruleport.LocalPort -join ","
					RemotePort = $ruleport.RemotePort -join ","
				} # End of hash table
				New-Object -TypeName psobject -Property $data}
		} # End of Script Block
	} # End of Process Block }
}
#---------------------------------------------------
#    BONUS LAB
#
# - Baseline all of the autostart locations
#
