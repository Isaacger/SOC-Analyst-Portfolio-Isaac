# Project 02 scenario, as run (Admin PowerShell). Times are UTC. No real passwords in this file.

# ---- Session 1: 20 Nov 2026 ----
$start = Get-Date; $start.ToUniversalTime()
$pw = Read-Host "Password for labuser" -AsSecureString                          # typed at a prompt: never on a command line (4688 logs it)
New-LocalUser -Name labuser -Password $pw -Description "P02 lab test account"   # 13:05:15  4720, 4722, 4724, 4738 x2
Add-LocalGroupMember -SID S-1-5-32-544 -Member labuser                          # 13:05:43  4732 (SID avoids the Spanish group name)

# Control group: failed validations for a user that does not exist (made-up passwords)
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine')
foreach ($fake in 'WrongPass-One1','WrongPass-Two2','WrongPass-Three3') { $ctx.ValidateCredentials('labfakeuser', $fake) }   # 13:08:21-25  4648, 4776, 4625 x3 (type 3, NTLM)
# Two more labfakeuser failures, at 13:08:13 and 13:11:43, are not in my command history (cause Unknown, see report finding 6)

Remove-LocalGroupMember -SID S-1-5-32-544 -Member labuser                       # 13:12:54  4733

# ---- Session 2: 21 Nov 2026 ----
Add-LocalGroupMember -SID S-1-5-32-544 -Member labuser                          # 10:34:34  4732 (admin again, for the split-token test)
# Typed by hand at the runas prompt: 3 wrong passwords, then the correct one (whoami, exit)
runas /user:labuser cmd                                                         # run 3 times, wrong password each time: 10:35:03, 10:35:15, 10:35:26  4625 + 4776 (type 2)
runas /user:labuser cmd                                                         # 10:36:02  4776, 4648, 4672, 4624 x2
Remove-LocalGroupMember -SID S-1-5-32-544 -Member labuser                       # 10:36:36  4733
Remove-LocalUser -Name labuser                                                  # 11:10:58  4726
Get-CimInstance Win32_UserProfile | Where-Object LocalPath -like '*\labuser' | Remove-CimInstance   # profile folder left behind by the deletion
