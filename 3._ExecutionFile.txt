
# Setup
$creds = Get-Credentials VAOC\student #ST@dm1n!ST@dm1n!
$allhosts = Import-Csv C:\path\to\Winhosts.csv

# Lab 3
$targets = $allhosts |
	Where-Object { $_.os -eq "Win10" } |
	Select-Object -ExpandProperty IP

Survey-Accounts -ComputerName $targets -Credential $creds |
	Export-Csv ./Win10UserAccounts.csv

# Lab 4
$targets = $allhosts |
	Where-Object { $_.os -eq "Win Server 2012R2"} |
	Select-Object -ExpandProperty IP

Survey-Services -ComputerName $targets -Credential $creds |
	Export-Csv ./WinSvr2012Services.csv

# Lab 5
$path = "C:\Windows\System32\drivers"
$targets = $allhosts |
	Where-Object { $_.os -eq "Win10" -and $_.subnet -eq "Shield" } |
	Select-Object -ExpandProperty IP

Survey-FileHash-ComputerName $targets -Credential $creds -Path $path |
	Export-Csv ./ShieldWin10Hashes.csv

# Lab 6
$targets = $allhosts |
	Where-Object { $_.os -eq "Win10" -and $_.subnet -eq "Shield" } |
	Select-Object -ExpandProperty IP

Survey-Processes -ComputerName $targets -Credential $creds |
	Export-Csv ./Win10Processes.csv

# Lab 7
$targets = $allhosts |
	Where-Object { $_.os -eq "Win Server 2012R2" -and $_subnet -eq "Rep/C2" } |
	Select-Object -ExpandProperty IP

Survey-Firewall -ComputerName $targets -Credential $creds |
	Export-Csv ./WinSvr2012Firewall.csv
