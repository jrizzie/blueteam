# -- LEAST FREQUENCY ANALYSIS -- #
#
## First go back to 2._LabFunctions.psm1 and -importmodule 2._LabFunctions.psm1
#
# Setup
$creds = Get-Credential -cr justin
$allhosts = Import-Csv C:\Users\jfizzie\Desktop\BASELINE\winhosts.csv
#------------------------------------------------------------------------
#
# 1:  LFA - PROCESSES --->
# run setup (top of page)
$targets = $allhosts |Select-Object -ExpandProperty IP
$targets.Count *.1
$procs = Survey-Processes -ComputerName $targets -Credential $creds
$procs | Sort-Object -Unique -Property pscomputername, hash |
                Group-Object hash | Where-Object count -le 1 |
                    Select-Object -ExpandProperty group 
#------------------------------------------------------------------------
#
# 2:  LFA - SERVICES --->
# run setup (top of page)
$targets = $allhosts |Select-Object -ExpandProperty IP
$targets.Count *.1
$procs = Survey-Services -ComputerName $targets -Credential $creds
$procs | Sort-Object -Unique -Property pscomputername, name |
                Group-Object name | Where-Object count -le 1 |
                    Select-Object -ExpandProperty group
#------------------------------------------------------------------------
#
# 3:  LFA - AUTORUNS --->
# run setup (top of page)
$targets = $allhosts |Select-Object -ExpandProperty IP
$targets.Count *.1
$procs = survey-AutoRuns -computername $targets -Credential $creds
$procs | Sort-Object -Unique -Property pscomputername, path, hash |
                Group-Object hash | Where-Object count -le 1 |
                    Select-Object -ExpandProperty group