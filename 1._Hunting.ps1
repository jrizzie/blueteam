$creds = Get-Credential -cr justin
$allhosts = Import-Csv C:\Users\jfizzie\Desktop\baseline\winhosts.csv
#
#============================   Test Connection  ============================
#
$creds = Get-Credential -cr justin
icm -cn 192.168.80.102 -cr $creds {hostname}
icm -cn 192.168.80.100 -cr $creds {hostname}
icm -cn 192.168.80.103 -cr $creds {hostname}
# ----- Run against all 3:
$targets = $allhosts |
    Select-Object -ExpandProperty IP
        icm -cn $targets -cr $creds {hostname}
#-
#============================   Sending/Receiving Files  ============================
#
#-----------Sending:
$session=New-PSSession -cn 192.168.80.100 -cr $creds
$arguments=@{
Path= "local-machine-path-to-source-file"
Destination= "target-path-and-destination"
ToSession= $session
            }
Copy-Item @arguments
Remove-PSSession $session
#
#-----------Receiving:
$session=New-PSSession -cn 192.168.80.100 -cr $creds
$arguments=@{
LiteralPath= "target-machine-path-to-source-file"
Destination= "local-machine-path-and-destination"
FromSession= $session
            }
Copy-Item @arguments
Remove-PSSession $session
#============================  HOW MANY LOGONS ARE THERE?  ============================
#>
$targets = $allhosts |
	    Select-Object -ExpandProperty ip
(icm -cn 192.168.80.100 -cr $creds -ScriptBlock {
    $logfilter = @{
        logname = "security"
        ID = "4624"
#        starttime = [datetime] "MM/DD/YYYY HH:MM:SS"
#        endtime   = [datetime] "MM/DD/YYYY HH:MM:SS"
        }
        Get-WinEvent -filterhashtable $logfilter
        }).count
#-
#============================  HOW MANY ACCOUNTS WERE CREATED?  ============================
#>
$targets = $allhosts | Select-Object -ExpandProperty ip
$target1 = @{
computername = $targets
credential = $creds
}
icm @target1 {
                $logfilter = @{}
                $logfilter.logname = "security"
                $logfilter.id = 4270,4728,4732,4756
            Get-WinEvent -FilterHashtable $logfilter | ?{$_.message -like "*$SID*"}
            } | Select-Object recordid, message | Format-List > newaccounts.csv  

#-
#============================ New Firewall rules created  ============================
#
$targets = $allhosts | Select-Object -ExpandProperty ip
$target2 = @{
computername = $targets
credential = $creds
}
icm @target2 {
                $logfilter = @{}
                $logfilter.logname = "*Firewall*"
                $logfilter.id = 2004
    Get-WinEvent -FilterHashtable $logfilter }| Select-Object timecreated, recordid, message | Format-Table -Wrap > new-firewall-logs.csv
#
#============================  Finding TEXT/NUMBERS!  ============================
#>
$targets = $allhosts |
    Select-Object -ExpandProperty IP
        icm -computername $targets -cr $creds {
            $expression = "\d{3}-\d{2}-\d{4}"
            $filepath = "$env:ALLUSERSPROFILE","$env:USERPROFILE" 
gci -path $filepath -Recurse | select-string -Pattern $expression -AllMatches -ErrorAction SilentlyContinue | fc} 
                    #Format-Table Path, Line -Wrap}
#bonus -- Add to this script; for every result returned- give me it's associated ip address and hostname                                                 
#-
#---------------  Find EMAILS:
#-
#replace $expression with "[\w\.-]+@[\w\.-]+\.[\w]{2,3}" 
#example:
gci -Recurse | Select-String -Pattern  "[\w\.-]+@[\w\.-]+\.[\w]{2,3}" -AllMatches
#-
#---------------  Find strings:
#-
#-                        FIND (THIS) -and- (THIS -or- THAT)
# replace $expression with "(?=.*STRING1)(?=.*STRING2|.*STRING3)"
#example:
gci -Recurse | Select-String -Pattern  "(?=.*jrizzie)" -AllMatches
gci -Recurse | Select-String -Pattern  "(?=.*jrizzie)(?=.*yahoo|.*.com)" -AllMatches
#-
#============================  Finding FILES!  ============================
#
icm -cn 192.168.80.100 -cr $creds {gci -path C:\ -Include *filename* -File -Recurse}
#-
#----- Hashing Files
#
icm -cn 192.168.80.100 -cr $creds {certutil.exe -hashfile "absolute-path-file.exe" SHA256}
icm -cn 192.168.80.100 -cr $creds {Get-FileHash -Algorithm SHA256 "absolute-path-file.exe"}
#-
#-                           _________________
#===========================|                 |============================#
#===========================|  START HUNTING  |============================#
#===========================|_________________|============================#
#
#
#-moloch/kibana -- Find outliers & anomalous traffic
#-moloch -> SPIview -> traffic/SMTP-emails/stuff
#-kibana -> top source host/dest || unique host/dest
#-kibana -> Remote Access traffic (22, 23)
#-kibana -> visualization for weird things (DNS-exfil)--(threat-focused)
#-kibana -> sysmon (windows security event logs)
#-kibana -> suricata alerts
#============================  Find Processes ============================
#-
#----- Execution File (survey processes/services) + Bonus: (use SysInternals:tcpview)
#-
icm -cn 192.168.80.103 -cr $creds {tasklist}
icm -cn 192.168.80.103 -cr $creds {tasklist /svc}
icm -cn 192.168.80.103 -cr $creds {netstat -ano}
#-
#----- is the process still running on the host machine?
$targets = $allhosts |
    Select-Object -ExpandProperty IP            
            Survey-Processes 192.168.80.100 -cr $creds | ?{$_.name -like "*wsmprov*"}
#-
#----- is the process running on other machines?
$targets = $allhosts |
#   ?{$_.os -eq "win10"}
    Select-Object -ExpandProperty IP            
            Survey-Processes $targets -cr $creds | ?{$_.name -like "*wsmprov*"}
#-
