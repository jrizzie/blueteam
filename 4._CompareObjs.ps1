#-
#============================ Compare old/new Firewall rules  ============================
#
#$creds = Get-Credential justin
$newtargets = Import-Csv C:\Users\jfizzie\Desktop\baseline\winhosts.csv | ?{$_.os -eq "win10"} | Select-Object -ExpandProperty IP
$ht = @{
    referenceobject = Import-Csv C:\Users\jfizzie\Desktop\baseline\winhosts.csv
    differenceobject = $null
    property = "direction", "action", "localaddress", "remoteaddress", "localport", "remoteport"
    passthru = $true }
$current = Survey-Firewall -ComputerName $newtargets -cr $creds
    foreach ($ip in $newtargets)
    {$ht.differenceobject = $current | ?{$_.pscomputername -eq $ip} |
        Sort-Object -Property direction, action, localaddress, remoteaddress, localport, remoteport -Unique
            Compare-Object @ht| Select-Object -Property *, @{name="ip-addr"; expression={$ip}}
    }
#-
#============================ Compare old/new installed Processes  ============================
#
$newtargets = Import-Csv C:\Users\jfizzie\Desktop\baseline\winhosts.csv | Select-Object -ExpandProperty IP
$ht2 = @{
    referenceobject  = Import-Csv C:\Users\jfizzie\Desktop\baseline\All-Processes-and-their-hashes.csv
    differenceobject = $null
    property         = "hash", "path"
    passthru         = $true
       }
$current = Survey-Processes -computername $newtargets -Credential $creds
    foreach ($ip in $newtargets)
    { 
    $ht2.differenceobject = $current |?{$_.pscomputername -eq $ip}
    Sort-Object -Property hash, path -Unique|
    Compare-Object @ht2 | Where-Object{$_sideindicator -eq "=>" -and $_.path -ne $null }
    }
#-
#============================ Compare old/new installed SERVICES  ============================
#
$newtargets = Import-Csv C:\Users\jfizzie\Desktop\baseline\winhosts.csv | Select-Object -ExpandProperty IP
$ht2 = @{
    referenceobject  = Import-Csv C:\Users\jfizzie\Desktop\baseline\All-Services.csv
    differenceobject = $null
    property         = "name"
    passthru         = $true
       }
$current = Survey-Services -computername $newtargets -Credential $creds
    foreach ($ip in $newtargets)
    { 
    $ht2.differenceobject = $current |?{$_.pscomputername -eq $ip}
    Sort-Object -Property name -Unique|
    Compare-Object @ht2 | Where-Object{$_sideindicator -eq "=>"}
    }
#-
#============================ Compare old/new running-processes  ============================
#
# -- pretty sure this is not working the way i intended it to?
#>
$newtargz = Import-Csv C:\Users\jfizzie\Desktop\baseline\winhosts.csv | Select-Object -ExpandProperty IP
$ht3 = @{
    referenceobject  = Import-Csv C:\Users\jfizzie\Desktop\baseline\ezprocs.csv
    differenceobject = $null
    property         = "PROCESSNAME"
    passthru         = $true
       }
$current = icm -cn $newtargz -cr $creds {Get-Process | Format-List -Property PROCESSNAME}
    foreach ($ip in $newtargz)
    {$ht3.differenceobject = $current |
        Sort-Object -Property PROCESSNAME -Unique
            Compare-Object @ht3| Select-Object -Property *, @{name="process"; expression={$ip}}
    }
#
#-
#============================ Compare old/new AUTORUNS  ============================
#
# -- I'll get around to it someday...
#---------------------------------------------------
# Lab 7