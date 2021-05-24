<#
    .SYNOPSIS
        Script to parse Bitvise SSH Server logs to make them more human-readable and useful for analysis objectives. 
    
    .PARAMETER Log
        Used depict the log file to parse.

    .EXAMPLE
        PS C:\ > .\BitviseParser.ps1 -log c:\BvSshServer20210520.log

        Executes the script and parses the BvSshServer20210520.log
#>

[CmdletBinding()]
param(
       $log
)

[xml]$file = Get-Content $log
$results = foreach ($line in $file.log.event){
    [pscustomobject]@{
        Sequence = $line.seq
        Time    = $line.time
        Name = $line.name
        Description = $line.desc
        Service = $line.session.service
        IP = $line.session.remoteaddress
        VirtualAccount  = $line.session.virtualaccount
        Continent  = $line.location.continent
        Country  = $line.location.continent
        IncorrectUsername = $line.authentication.userName
        AuthenticationMethod = $line.authentication.method
        HelpMessage = $line.help.message
        Code = $line.sfs.code
        EventDescription = $line.sfs.desc
        ErrorMessage = $line.sfs.error.message
        Path = $line.sfs.parameters.path
        Upload = $line.sfs.parameters.upload
        Download = $line.sfs.parameters.download
        finalSize = $line.sfs.parameters.finalSize
        StatusCode = $line.sfs.parameters.statusCode
        BlacklistedUser = $line.parameters.username
        Client = $line.parameters.clientversion
        User = $line.session.windowsAccount
    }
}
$results | Export-Csv ".\BitviseParsed.csv" -NoTypeInformation -Force