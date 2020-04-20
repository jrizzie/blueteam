## First go back to 2._LabFunctions.psm1 and -importmodule 2._LabFunctions.psm1

# Setup
$creds = Get-Credential -cr justin
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
$targets = $allhosts |
    Where-Object { $_.os -eq "win10"} |	
        Select-Object -ExpandProperty IP
            Survey-Firewall -ComputerName $targets -cr $creds |
	            Export-Csv ./All-Firewall-rules.csv


# ---Bonus Lab---
#
# Survey & baseline all the autostart locations
#
#- 
#--------------   EXTRA BASELINE INFO  --------------

    $targets = $allhosts |
        Select-Object -ExpandProperty IP
            icm -cn $targets -cr $creds {Get-Process | Format-List -Property PROCESSNAME} > ezprocs.csv

    $targets = $allhosts |
        Select-Object -ExpandProperty IP
            icm -cn $targets -cr $creds {tasklist /svc} > tasklist-svcs.csv
	    
            
#--------------   BONUS:   Compare old/new tasklist info (filtered on IMAGENAME)  --------------
#--------------   BONUS-2:   compare COUNT of # processes if more than one        --------------

