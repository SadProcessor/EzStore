## EzStore.ps1

<#
.SYNOPSIS
 Easy Storing of Stuff
.DESCRIPTION
 Stash & Fetch stuff
 Like a PowerShell pocket or something
.EXAMPLE
 EzStore Greeting 'HelloWorld' [$Description]
 .EXAMPLE
 EzStore [-List] [$Key]
.EXAMPLE
 EzStore Greeting
.EXAMPLE
 EzStore -Load $JSON
.EXAMPLE
 EzStore -Flush
.NOTES
Uses PowerShell.Secret.Management and PowerShell.Secret.Store

- Installs Modules if not avail on system.
- Registers 'No Password' vault as storage. <-------- ZeroTouch ??
- Collects pipeline input before storage.
- Converts all storage input to JSON.
- Converts all storage output from JSON.
- Bulk load JSON from json/file/repo.
-Tries to maintain Item Type.

/!\ This is not a secure vault /!\

https://devblogs.microsoft.com/powershell/secretmanagement-and-secretstore-are-generally-available/
#>
function Invoke-EzStore{
    [CmdletBinding(DefaultParameterSetName='Read')]
    [Alias('EzStore','EzS','Stash')]
    Param(
        # Item Name
        [Parameter(Mandatory=0,Position=0,ParameterSetName='List')]
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Write')]
        [Parameter(Mandatory=0,Position=0,ParameterSetName='Read')][Alias('Item')][String]$Key,
        # Item Value
        [Parameter(Mandatory=1,Position=1,ParameterSetName='Write',ValueFromPipeline=1)]$Value,
        # List items / Description
        [Parameter(Mandatory=1,ParameterSetName='List')][Switch]$List,
        # Set Item Description
        [Parameter(Mandatory=0,Position=2,ParameterSetName='Write')][String]$Description,
        # Bulk Load Items
        [Parameter(Mandatory=1,ParameterSetName='Load')][String]$Load,
        # Remove Stach
        [Parameter(Mandatory=1,ParameterSetName='Flush')][Switch]$Flush,
        # Create Var
        [Parameter(Mandatory=0,ParameterSetName='Read')][Switch]$AsVar,
        # Invoke
        [Parameter(Mandatory=0,ParameterSetName='Read')][Alias('x')][Switch]$Invoke
        )
    Begin{
        # SetName
        $SetName = $PSCmdlet.ParameterSetName
        if($SetName -eq 'Read' -AND -Not$Key){$SetName = 'List'}
        # Module Check & Install
        if(-not(Get-PackageProvider | Where-Object name -eq NuGet)){
            $Null = Install-PackageProvider -Name 'NuGet' -MinimumVersion 2.8.5.201 -Scope 'CurrentUser' -Force -Verbose:$false
            }
        if(-Not(Get-Command Get-SecretStoreConfiguration -ea 0)){
            Find-Module Microsoft.PowerShell.SecretStore -IncludeDependencies |
            Install-Module -Scope CurrentUser -SkipPublisherCheck -AllowClobber -Force
            }
        # Vault Check & Install
        if(-Not(Get-SecretVault | Where-Object name -eq EzStore)){
            # Register Vault
            $VaultParams = @{Authentication='None'; Interaction='None'; Scope='CurrentUser'}
            Set-SecretStoreConfiguration -Scope 'CurrentUser' -Authentication 'None' -PasswordTimeout 3600 -Interaction 'None' -Password ('EzStore'|ConvertTo-SecureString -AsPlainText -Force) -Confirm:$false
            Register-SecretVault -ModuleName Microsoft.PowerShell.SecretStore -Name EzStore -VaultParameters $VaultParams
            }
        # Prep Collector
        if($SetName -eq 'Write'){[Collections.ArrayList]$Collector=@()}
        }
    # Collect Pipeline input
    Process{if($SetName -eq 'Write'){Foreach($Obj in $Value){$Null = $Collector.Add($Obj)}}}
    # Switch ParameterSetName
    End{Switch($SetName){
            # READ
            Read{
                # Get Item
                $Cast = if(((EzStore | Where-Object Item -eq $Key).type)){(EzStore | Where-Object Item -eq $Key).type}else{'PSCustomObject'}
                $out = Get-Secret -Vault EzStore -Name $Key -AsPlainText -ea 0| Convertfrom-Json -ea 0
                # Output
                $Out = if($Cast -eq 'System.DateTime'){($Out)|Foreach-Object{$_.DateTime -as $Cast}}
                elseif($Cast -eq 'System.Management.Automation.ScriptBlock'){($Out)|Foreach-Object{[ScriptBlock]::Create($_)}}
                else{Try{($Out)|Foreach-Object{$_-as $Cast}}Catch{$Out}}
                # Invoke
                if($Cast -eq 'System.Management.Automation.ScriptBlock' -AND $Invoke){$Out|Invoke-Expression}
                # As Var
                elseif($AsVar){New-Variable -Name $Key -Value $Out -Scope 'Global' -force}else{$out}
                }
            ## WRITE
            Write{
                # Get Item Type
                $ObjType = if(($Collector|Foreach-Object{$_.gettype().Fullname}|Sort-object -unique).count -gt 1){'PSCustomObject'}else{($Collector|Select-Object -first 1).gettype().Fullname}
                if($ObjType -eq 'System.Management.Automation.ScriptBlock'){$Collector = @($Collector|Foreach-Object{$_.tostring()})}
                # Transform to JSON String
                $ToJSON = $Collector | ConvertTo-Json -Compress
                # Set Key/Value
                Set-Secret -Vault EzStore -Name $Key -Secret $ToJSON
                # Add Props
                Set-SecretInfo -Vault EzStore -Name $Key -Metadata @{Type=$ObjType}
                if($Description){Set-SecretInfo -Vault EzStore -Name $Key -Metadata @{Description=$Description}}
                }
            ## LIST
            List{
                $Out = Get-SecretInfo -Vault EzStore | Select-Object @{Name='Item';Ex={$_.Name}},@{Name='Description';Ex={($_|Select-Object -expand metadata).Description}},@{Name='Type';Ex={($_|Select-Object -expand metadata).Type}}
                if($Key){$Out|Where-Object Item -eq $Key}else{$Out}
                }
            ## LOAD
            Load{# Ingest
                # -----> # JSON
                $Ingest = if($Load -match "^\[\{"){$Load}
                         # Repo
                         elseif($Load -match "^https\:"){Invoke-WebRequest $Load -UseBasicParsing | Select-Object -expand content}
                         # else
                         else{Get-Content $Load}
                # Test JSON
                $Ingest = $(try{$Ingest|ConvertFrom-Json}catch{}) | Where-Object {$_.Item -AND $_.Value}
                # Load foreach
                Foreach($Obj in ($Ingest)){
                    Set-Secret -Vault EzStore -Name $Obj.item -Secret ($Obj.Value| ConvertTo-Json -Compress)
                    if($Obj.Type){Set-SecretInfo -Vault EzStore -Name $Obj.item -Metadata @{Type=$Obj.Type}}
                    if($Obj.description){Set-SecretInfo -Vault EzStore -Name $Obj.item -Metadata @{Description=$Obj.description}}
                    }}
            ## FLUSH
            Flush{# Reset & unregister
                Reset-SecretStore -Authentication 'None' -Interaction 'None' -Force -WarningAction 0
                Unregister-SecretVault -Name EzStore -ea 0
                #Remove-Module -name Microsoft.PowerShell.SecretStore -Force
                }}}}
#############End
