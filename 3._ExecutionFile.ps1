#
# Setup
$creds = Get-Credential justin
$allhosts = Import-Csv C:\Users\jfizzie\Desktop\SURVEY\winhosts.csv
#------------------------------------------------------------------------

# Lab 3
$targets = $allhosts |
	    Select-Object -ExpandProperty IP
            Survey-Accounts -ComputerName $targets -Credential $creds |
	            Export-Csv ./ALL-UserAccounts.csv

# Lab 4
$targets = $allhosts |
	Select-Object -ExpandProperty IP
        Survey-Services -ComputerName $targets -Credential $creds |
	        Export-Csv ./All-Services.csv

# Lab 5
$path = "C:\Windows\System32\drivers"
$targets = $allhosts |
	Select-Object -ExpandProperty IP
        Survey-FileHash -ComputerName $targets -Credential $creds -Path $path |
	        Export-Csv ./survey-filehash-All-sys32-drivers.csv

# Lab 6
$targets = $allhosts |
	Select-Object -ExpandProperty IP
        Survey-Processes -ComputerName $targets -Credential $creds |
	        Export-Csv ./All-Processes-and-their-hashes.csv

# Lab 7
$creds = Get-Credential justin
$allhosts = Import-Csv C:\Users\jfizzie\Desktop\SURVEY\winhosts.csv
$targets = $allhosts |
    Where-Object { $_.os -eq "win10"} |	
        Select-Object -ExpandProperty IP
            Survey-Firewall -ComputerName $targets -Credential $creds |
	            Export-Csv ./All-Firewall-rules.csv

# getting fancier --
#>
$targets = $allhosts |
    Where-Object { $_.os -eq "win10" -and $_subnet -eq "critical" } |
	    
            

