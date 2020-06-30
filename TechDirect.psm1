<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.167
	 Created on:   	9/3/2019 8:37 AM
	 Created by:   	Dakota Zinn
	 Organization: 	N/A
	 Filename:     	TechDirect.psm1
	-------------------------------------------------------------------------
	 Module Name: TechDirect
	===========================================================================
#>

function New-TDInvocation
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "Doesn't make an changes")]
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $false)]
	[OutputType([hashtable])]
	param
	(
		[String]$Uri,
		[ValidateSet('Get', 'Put', 'Post', 'Delete')]
		[string]$Method = "Post",
		$Body,
		[hashtable]$Headers = @{ Authorization = "Bearer $((Get-TDAccessToken).access_token)" },
		[String]$ContentType = "text/xml"
	)
	
	$invocation = @{
		Uri		    = $Uri
		Method	    = $Method
		Headers	    = $Headers
		ContentType = $ContentType
	}
	if ($Body)
	{ $invocation.Add("Body", $Body) }
	return $invocation
}

function Connect-TechDirect
{
	<#
		.SYNOPSIS
			This function will acquire an Access Token from TechDirect
		
		.DESCRIPTION
			This function will acquire an Access Token from TechDirect for use with TechDirect Warranty and Self-Dispatch APIs
		
		.PARAMETER Warranty
			Used to incidate a request for a Warranty API Token
		
		.PARAMETER Dispatch
			Used to incidate a request for a Self-Dispatch API Token
		
		.PARAMETER Sandbox
			Used to request a token using the sandbox environment.
			Sandbox is not available for the Warranty API.
		
		.PARAMETER ClientID
			Client ID provided by TechDirect for your API access.
		
		.PARAMETER ClientSecret
			Client Secret provided by TechDirect for your API access.
		
		.EXAMPLE
			PS C:\> Connect-TechDirect -ClientID 'ABCDEFGHIJKL' -ClientSecret 'ZYXWVUTSRQPONML'
		
		.EXAMPLE
			PS C:\> Connect-TechDirect -ClientID 'ABCDEFGHIJKL' -ClientSecret 'ZYXWVUTSRQPONML' -Sandbox
		
		.NOTES
			Additional information about the function.
	#>
	
	[CmdletBinding(DefaultParameterSetName = 'Warranty',
				   ConfirmImpact = 'None',
				   PositionalBinding = $true,
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	param
	(
		[Parameter(ParameterSetName = 'Warranty',
				   Position = 1)]
		[switch]$Warranty,
		[Parameter(ParameterSetName = 'Dispatch',
				   Position = 1)]
		[switch]$Dispatch,
		[Parameter(ParameterSetName = 'Dispatch',
				   Position = 2)]
		[switch]$Sandbox,
		[Parameter(Mandatory = $true)]
		[string]$ClientID,
		[Parameter(Mandatory = $true)]
		[string]$ClientSecret
	)
	
	$Bytes = [System.Text.Encoding]::UTF8.GetBytes($($ClientID + ":" + $ClientSecret))
	$Base64Key = [System.Convert]::ToBase64String($Bytes)
	$Header = @{ Authorization = "Basic $Base64Key" }
	$Body = "grant_type=client_credentials"
	if ($sandbox)
	{ $Endpoint = "apigtwb2cnp.us.dell.com" }
	else { $Endpoint = "apigtwb2c.us.dell.com" }
	
	Try
	{
		$Token = Invoke-RestMethod "https://$Endpoint/auth/oauth/v2/token" -Method Post -Body $Body -ContentType "application/x-www-form-urlencoded" -Headers $Header
		if ($sandbox)
		{ $Token | Add-Member -MemberType NoteProperty -Name sandbox -Value $True }
		else { $Token | Add-Member -MemberType NoteProperty -Name sandbox -Value $False }
		$Token | Add-Member -MemberType NoteProperty "expire_time" -Value (Get-Date).AddSeconds($Token.expires_in) -Force
		if (!(Test-Path "$env:LOCALAPPDATA\TechDirect\"))
		{ New-Item -Path "$env:LOCALAPPDATA\TechDirect\" -ItemType directory -Force | Out-Null }
		if ($Warranty)
		{
			$Token | Add-Member -MemberType NoteProperty "expire_time" -Value (Get-Date).AddSeconds($Token.expires_in) -Force
			$Token | ConvertTo-Json | Out-File $env:LOCALAPPDATA\TechDirect\Token-W.json -Force
		}
		elseif ($Dispatch)
		{
			$Token | Add-Member -MemberType NoteProperty "expire_time" -Value (Get-Date).AddSeconds($Token.expires_in) -Force
			$Token | ConvertTo-Json | Out-File $env:LOCALAPPDATA\TechDirect\Token-D.json -Force
		}
		Write-Output "`r`nSuccessfully acquired TechDirect token.`r`n"
		return $Token
	}
	catch
	{
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		$statuscode = $_.Exception.Response.StatusCode.value__
		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($(($Response | ConvertFrom-Json).error_description), "$statuscode", $ErrCategory, $Null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
	}
}

function Get-TDAccessToken
{
	[CmdletBinding()]
	param
	(
		[switch]$Warranty,
		[switch]$Dispatch
	)
	if ($Warranty)
	{
		$TokenPath = "$env:LOCALAPPDATA\TechDirect\Token-W.json"
		if (Test-Path $TokenPath)
		{
			try { $TokenInfo = Get-Content $TokenPath | ConvertFrom-Json }
			catch
			{
				$ErrCategory = [system.management.automation.errorcategory]::SecurityError
				$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Token at '$TokenPath' does not exist or is corrupted, use 'Connect-TechDirect' to acquire a token`r`nError Info can be found in `$error[0].TargetObject", "", $ErrCategory, $_)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		}
		else
		{
			$ErrCategory = [system.management.automation.errorcategory]::SecurityError
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Token does not exist at '$TokenPath', use 'Connect-TechDirect' to acquire a token.", "", $ErrCategory, $_)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
	elseif ($Dispatch)
	{
		$TokenPath = "$env:LOCALAPPDATA\TechDirect\Token-D.json"
		if (Test-Path $TokenPath)
		{
			try { $TokenInfo = Get-Content $TokenPath | ConvertFrom-Json }
			catch
			{
				$ErrCategory = [system.management.automation.errorcategory]::SecurityError
				$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Token at '$TokenPath' does not exist or is corrupted, use 'Connect-TechDirect' to acquire a token`r`nError Info can be found in `$error[0].TargetObject", "", $ErrCategory, $_)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		}
		else
		{
			$ErrCategory = [system.management.automation.errorcategory]::SecurityError
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Token does not exist at '$TokenPath', use 'Connect-TechDirect' to acquire a token", "", $ErrCategory, $null)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
	else
	{ return }
	
	$UTCOffset = [System.TimeZoneInfo]::Local.GetUtcOffset((get-date)).totalminutes
	$TokenInfo.expire_time = $TokenInfo.expire_time.AddMinutes($UTCOffset)
	$TokenInfo.expires_in = [math]::Round((New-timespan (get-date) $TokenInfo.expire_time).TotalSeconds, 0)
	if ($TokenInfo.expire_time -le (get-date))
	{
		$ErrCategory = [system.management.automation.errorcategory]::AuthenticationError
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Token is expired, use 'Connect-TechDirect' to acquire a new token", "", $ErrCategory, $Null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		return
	}
	return $TokenInfo
}

function Format-DispatchPart
{
	param ([string]$PartNumber,
		[string]$PPID,
		[int]$Quantity)
	$part = [System.Text.StringBuilder]"<api:PartInfo>`r`n"
	$Part.Append("`t<api:PartNumber>$PartNumber</api:PartNumber>`r`n")
	if ($PPID)
	{ $Part.Append("`t<api:PPID>$PPID</api:PPID>`r`n") }
	else { $Part.Append("`t<api:PPID/>`r`n") }
	$Part.Append("`t<api:Quanitity>$Quantity</api:Quanitity>`r`n")
	$part.Append("</api:PartInfo>")
	return $part.ToString()
}

function Format-DispatchAttachment
{
	param
	(
		[string]$Description,
		[string]$FilePath
	)
	Begin { Add-Type -AssemblyName "System.Web" }
	Process
	{
		$FileName = (Get-Item $FilePath).Name
		if ($Description -eq "")
		{ $Description = $FileName }
		
		$MIMEType = [System.Web.MimeMapping]::GetMimeMapping("$FilePath")
		$FileData = Convert-FileToBase64 $FilePath
		$XML = @"
<api:AttachmentInfo>
<api:Description>$Description</api:Description>
<api:FileName>$FileName</api:FileName>
<api:MIMEType>$MIMEType</api:MIMEType>
<api:Data>$FileData</api:Data>
</api:AttachmentInfo>
"@
		return $XML
	}
}

function Get-TechnicianStatus
{
	<#
		.SYNOPSIS
			Check Technician Status.
		
		.DESCRIPTION
			Provides account level details. Account should be active and not expired
			for API transactions to complete.
		
		.PARAMETER Credentials
			Credential Object containing the Username/Password of the Technician
		
		.EXAMPLE
			$Credentials = (Get-Credential)
			PS C:\> Get-TechnicianStatus -Credentials $Credentials
		
	#>
	
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	param
	(
		[Parameter(Mandatory = $false)]
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:")
	)
	
	$Username = ($PSboundparameters.Credentials).getnetworkcredential().Username
	$Password = ($PSboundparameters.Credentials).getnetworkcredential().Password
	
	$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
   <soapenv:Header/>
   <soapenv:Body>
      	<api:CheckUser>
         	<api:CheckUserRequest>
            	<api:Login>$Username</api:Login>
            	<api:Password>$Password</api:Password>
         	</api:CheckUserRequest>
      	</api:CheckUser>
   	</soapenv:Body>
</soapenv:Envelope>
"@
	$DellToken = Get-TDAccessToken -Dispatch
	if ($DellToken.sandbox)
	{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
	else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
	$Headers = @{
		Authorization = "Bearer $($DellToken.access_token)"
		SOAPAction    = "http://api.dell.com/IDispatchService/CheckUser"
	}
	
	try
	{
		$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
		$Result = $Response.Envelope.Body.CheckUserResponse.CheckUserResult.LoginResult
		####### We have to parse the XML response manually, since Powershell doesn't want to convert it to JSON natively
		$JSON = [pscustomobject]@{
			FullName = $Result.FullName
			Role	 = $Result.Role
			PasswordExpirationDate = [datetime]$Result.PasswordExpirationDate
			Inactive = $Result.Inactive
			Locked   = $Result.Locked
		}
		return $JSON
	}
	catch
	{
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
		$statuscode = $_.Exception.Response.StatusCode.value__
		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "$statuscode", $ErrCategory, $Null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
	}
}

function Get-TechnicianInfo
{
	<#
		.SYNOPSIS
			Get detailed information about Technician
		
		.DESCRIPTION
			A detailed description of the Get-TechnicianInfo function.
		
		.PARAMETER Credentials
			Credential Object containing the Username/Password of the Technician
		
		.EXAMPLE
			PS C:\> Get-TechnicianInfo
	#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:")
	)
	
	$Username = ($PSboundparameters.Credentials).getnetworkcredential().Username
	$Password = ($PSboundparameters.Credentials).getnetworkcredential().Password
	
	$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
	<soapenv:Header/>
	<soapenv:Body>
    	<api:CheckLogin>
        	<api:CheckLoginRequest>
            	<api:Login>$Username</api:Login>
            	<api:Password>$Password</api:Password>
        	</api:CheckLoginRequest>
      	</api:CheckLogin>
	</soapenv:Body>
</soapenv:Envelope>
"@
	
	$DellToken = Get-TDAccessToken -Dispatch
	if ($DellToken.sandbox)
	{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
	else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
	$Headers = @{
		Authorization = "Bearer $($DellToken.access_token)"
		SOAPAction    = "http://api.dell.com/IDispatchService/CheckLogin"
	}
	
	Try
	{
		$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
		$Result = $Response.Envelope.Body.CheckLoginResponse.CheckLoginResult.LoginResult
		
		
		####### We have to parse the XML response manually, since Powershell doesn't want to convert it to JSON natively
		$Relationships = $Result.Relationships.RelationshipInfo
		$Groups = @()
		foreach ($Relationship in $Relationships)
		{
			$Group = [pscustomobject]@{
				BranchName = $Relationship.BranchName
				CustomerName = $Relationship.CustomerName
				Track	   = $Relationship.Track
			}
			$Groups += $Group
		}
		
		$Certs = $Result.Certificates.CertificateInfo
		$Certifications = @()
		
		foreach ($cert in $Certs)
		{
			$Certificate = [pscustomobject]@{
				Certificate = $cert.certificate
				ExpirationDate = $cert.ExpirationDate
			}
			$Certifications += $Certificate
		}
		
		$JSON = [pscustomobject]@{
			FullName = $Result.FullName
			Role	 = $Result.Role
			PasswordExpirationDate = [datetime]$Result.PasswordExpirationDate
			HomeBranch = $Result.HomeBranch
			Relationships = $Groups
			Certificates = $Certifications
			DSP	     = $Result.DSP
		}
		return $JSON
	}
	
	catch
	{
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
		$statuscode = $_.Exception.Response.StatusCode.value__
		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "$statuscode", $ErrCategory, $Null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
	}
}

function Invoke-DispatchRequest
{
	<#
		.SYNOPSIS
			Initiate dispatch with TechDirect
		
		.DESCRIPTION
			Function to initiate a request for parts. This request is asynchronous, a Work Order is returned on successfully transacting with the Dispatch system.
			The WO number can then be queried to track the status of the Work Order.
			
			'Get-DispatchStatus' will be the primary method to track status of an WO.
			'Get-Dispatches' function can be used for querying more than one WO.
			
			For successful processing of a WO always submit -
			i. Contact information
			ii. Shipping information
			iii. Parts information
			iv. Service tag of the failed system
			v. Troubleshooting notes and evidence of failure.
		
		.PARAMETER Credentials
			Credential Object containing the Username/Password of the Technician
		
		.PARAMETER TechEmail
			Contains the email of the technician
			responsible for the dispatch. In the case of a logistics user this may be different from the login email
		
		.PARAMETER Branch
			Contains the branch associated with the
			dispatch. Note that the technician must be
			authorized to dispatch parts from this branch
		
		.PARAMETER Customer
			Contains the customer associated with the dispatch.
			The customer must have a valid relationship with the branch in order to successfully dispatch
		
		.PARAMETER Track
			Contains the track associated with the Branch
			to Customer relationship (this can be obtained using 'Get-TechnicianInfo')
		
		.PARAMETER ServiceTag
			The service tag associated with the dispatch
		
		.PARAMETER PrimaryContactName
			The primary contact associated with the dispatch.
		
		.PARAMETER PrimaryContactPhone
			The primary contact phone number for the dispatch
		
		.PARAMETER PrimaryContactEmail
			The primary contact email associated with the dispatch.
		
		.PARAMETER AlternateContactName
			Additional/Alternate contact name
		
		.PARAMETER AlternateContactPhone
			Additional/Alternate contact
			number
		
		.PARAMETER ReferencePONumber
			Optional purchase order or internal reference number
		
		.PARAMETER AddressBookName
			The name of a personal or company address book entry. If this  is specified the detail address parameters are not allowed.
		
		.PARAMETER CountryISOCode
			ISO country code for the ship-to address
		
		.PARAMETER City
			The ship-to city
		
		.PARAMETER State
			The ship-to state
		
		.PARAMETER ZipCode
			The ship-to zip or postal code
		
		.PARAMETER AddressLine1
			The first ship-to address line
		
		.PARAMETER AddressLine2
			The second ship-to address line
		
		.PARAMETER AddressLine3
			The third ship-to address line
		
		.PARAMETER TimeZone
			A description of the TimeZone parameter.
		
		.PARAMETER RequestCompleteCare
			A true/false parameter indicating if accidental damage applies to this dispatch
		
		.PARAMETER RequestReturnToDepot
			A true/false parameter indicating if return to depot applies to this dispatch
		
		.PARAMETER RequestOnSiteTechnician
			A true/false parameter indicating if an onsite technician is requested
		
		.PARAMETER TroubleshootingNote
			Contains troubleshooting notes, limited to 1000 characters
		
		.PARAMETER Parts
			An array of part information associated with the dispatch.
			This is limited to a maximum of 4 parts per dispatch
			
			Use 'Get-PartsByServiceTag' to query replaceable parts;
			Use 'Format-DispatchPart' to create each part;
		
		.PARAMETER Attachments
			An array of attachments to include with the dispatch.
			
			Use 'Format-DispatchAttachment' to create each attachment.
			
			PS C:\> $attachments = @(
			(Format-DispatchAttachment -filepath 'c:\temp\file.png' -description 'This thing is broken')
			(Format-DispatchAttachment -filepath 'c:\temp\secondfile.jpg' -description 'This is broken too')
			)
		
		.EXAMPLE
			PS C:\> $attachments = @(
			(Format-DispatchAttachment -filepath 'c:\temp\file.png' -description 'This thing is broken')
			(Format-DispatchAttachment -filepath 'c:\temp\secondfile.jpg' -description 'This is broken too')
			)
		
			PS C:\> $Parts = @(
			(Format-DispatchPart -PartName 
			)
		
			PS C:\> Invoke-DispatchRequest -Credentials -Email 'Value2' -Branch 'Value3' -Customer 'Value4' -Track 'Value5' -ServiceTag 'Value6' -PrimaryContactName 'Value7' -PrimaryContactPhone 'Value8' -PrimaryContactEmail 'Value9' -CountryISOCode 'Value10' -City 'Value11' -State 'Value12' -ZipCode 'Value13' -AddressLine1 'Value14' -AddressLine2 'Value15' -AddressLine3 'Value16' -TimeZone 'Value17' -RequestCompleteCare $value18 -RequestReturnToDepot $value19 -RequestOnSiteTechnician $value20 -TroubleshootingNote 'Value21'
		
		.EXAMPLE
			
			PS C:\> $paramInvokeDispatchRequest = @{
				Credentials			= $Credentials
				TechEmail			    	= "apiuser_us_tech01@uatmail.com"
				Branch				    = "US Group"
				Customer			    	= "Round Rock Customer"
				Track				    	= "Tier 1"
				ServiceTag			    	= "BR5424J"
				PrimaryContactName	    	= "One,Technician"
				PrimaryContactPhone	    	= "1111111111"
				PrimaryContactEmail	    	= "apiuser_us_tech01@uatmail.com"
				CountryISOCode		    	= $true
				AddressLine1		    	= "1"
				AddressLine2		    	= "Main"
				AddressLine3		   	= "Street"
				City				    	= "New York"
				State				    	= "NY"
				ZipCode				= "11111"
				TimeZone			    	= "US/Central"
				RequestCompleteCare	    	= $false
				RequestReturnToDepot    	= $false
				RequestOnSiteTechnician 	= $false
				TroubleshootingNote	    	= "THIS IS A TEST"
				Attachments = @(
					(Format-DispatchAttachment -FilePath 'c:\Temp\file (1).xlsx')
					(Format-DispatchAttachment -FilePath "c:\Temp\file.xlsx" -Description "This is a file")
				)
				Parts = @((Format-DispatchPart -PartNumber "MBD" -Quantity 1 -PPID "2148242621834394587"))
			}
	
			PS C:\> Invoke-DispatchRequest @paramInvokeDispatchRequest
	
	
		
	#>
	
	[CmdletBinding(DefaultParameterSetName = 'No Address Book',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	[OutputType([pscustomobject])]
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:"),
		[Parameter(Mandatory = $true,
				   Position = 2)]
		[Alias('Email')]
		[string]$TechEmail,
		[Parameter(Mandatory = $true,
				   Position = 3)]
		[string]$Branch,
		[Parameter(Mandatory = $true,
				   Position = 4)]
		[Alias('CustomerName')]
		[string]$Customer,
		[Parameter(Mandatory = $true,
				   Position = 5)]
		[string]$Track,
		[Parameter(Mandatory = $true,
				   Position = 6)]
		[Alias('SerialNumber')]
		[string]$ServiceTag,
		[Parameter(Mandatory = $true,
				   Position = 7)]
		[string]$PrimaryContactName,
		[Parameter(Mandatory = $true,
				   Position = 8)]
		[string]$PrimaryContactPhone,
		[Parameter(Mandatory = $true,
				   Position = 9)]
		[string]$PrimaryContactEmail,
		[Parameter(Position = 10)]
		[string]$AlternateContactName,
		[Parameter(Position = 11)]
		[string]$AlternateContactPhone,
		[Parameter(Mandatory = $false,
				   Position = 12)]
		[string]$ReferencePONumber,
		[Parameter(ParameterSetName = 'Using Address Book',
				   Position = 13)]
		[string]$AddressBookName,
		[Parameter(ParameterSetName = 'No Address Book',
				   Position = 13)]
		[string]$CountryISOCode,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 14)]
		[string]$City,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 15)]
		[string]$State,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 16)]
		[string]$ZipCode,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 17)]
		[string]$AddressLine1,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 18)]
		[string]$AddressLine2,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 19)]
		[string]$AddressLine3,
		[Parameter(ParameterSetName = 'No Address Book',
				   Mandatory = $false,
				   Position = 20)]
		[string]$TimeZone,
		[Parameter(Mandatory = $true,
				   Position = 21)]
		[boolean]$RequestCompleteCare,
		[Parameter(Mandatory = $true,
				   Position = 22)]
		[boolean]$RequestReturnToDepot,
		[Parameter(Mandatory = $true,
				   Position = 23)]
		[boolean]$RequestOnSiteTechnician,
		[Parameter(Mandatory = $true,
				   Position = 24)]
		[ValidateLength(0, 1000)]
		[string]$TroubleshootingNote,
		[Parameter(Mandatory = $true,
				   Position = 25)]
		[array]$Parts,
		[Parameter(Position = 26)]
		[array]$Attachments
	)
	
	$Username = ($PSboundparameters.Credentials).getnetworkcredential().Username
	$Password = ($PSboundparameters.Credentials).getnetworkcredential().Password
	
	$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
	<soapenv:Header/>
	<soapenv:Body>
	    <api:CreateDispatch>
	        <api:CreateDispatchRequest>
	            <api:Login>$Username</api:Login>
	            <api:Password>$Password</api:Password>
                    <api:Dispatch>
	                    <api:TechEmail>$TechEmail</api:TechEmail>
	                    <api:Branch>$Branch</api:Branch>
	                    <api:Customer>$Customer</api:Customer>
	                    <api:Track>$Track</api:Track>
	                    <api:ServiceTag>$ServiceTag</api:ServiceTag>
	                    <api:PrimaryContactName>$PrimaryContactName</api:PrimaryContactName>
	                    <api:PrimaryContactPhone>$PrimaryContactPhone</api:PrimaryContactPhone>
	                    <api:PrimaryContactEmail>$PrimaryContactEmail</api:PrimaryContactEmail>`r`n
"@
	if ($AlternateContactName)
	{
		$XML += @"
						<api:AlternativeContactName>$AlternateContactName</api:AlternativeContactName>
	                    <api:AlternativeContactPhone>$AlternateContactPhone</api:AlternativeContactPhone>`r`n
"@
	}
	else
	{
		$XML += @"
						<api:AlternativeContactName/>
						<api:AlternativeContactPhone/>`r`n
"@
	}
	$XML += @"
						<api:ShipToAddress>`r`n
"@
	if ($AddressBookName)
	{
		$xml += @"
                            <api:AddressBookName>$AddressBookName</api:AddressBookName>`r`n
"@
	}
	else
	{
		$xml += @"
                            <api:AddressBookName/>`r`n
"@
	}
	$XML += @"
                            <api:CountryISOCode>$CountryISOCode</api:CountryISOCode>
                            <api:City>$City</api:City>
                            <api:State>$State</api:State>
                            <api:ZipPostalCode>$ZipCode</api:ZipPostalCode>
                            <api:AddressLine1>$AddressLine1</api:AddressLine1>`r`n
"@
	if ($AddressLine2)
	{
		$XML += @"
                            <api:AddressLine2>$AddressLine2</api:AddressLine2>`r`n
"@
	}
	else { $xml += "`t`t`t`t`t`t`t<api:AddressLine2/>`r`n" }
	if ($AddressLine3)
	{
		$xml += @"
                            <api:AddressLine3>$AddressLine3</api:AddressLine3>`r`n
"@
	}
	else { $xml += "`t`t`t`t`t`t`t<api:AddressLine3/>`r`n" }
	
	
	$XML += @"
                            <api:TimeZone>$TimeZone</api:TimeZone>
	           			</api:ShipToAddress>
                        <api:ReferencePONumber>$ReferencePONumber</api:ReferencePONumber>
						<api:RequestCompleteCare>$($RequestCompleteCare.ToString().ToLower())</api:RequestCompleteCare>
		               	<api:RequestReturnToDepot>$($RequestReturnToDepot.ToString().ToLower())</api:RequestReturnToDepot>
		               	<api:RequestOnSiteTechnician>$($RequestOnSiteTechnician.ToString().ToLower())</api:RequestOnSiteTechnician>
		               	<api:TroubleshootingNote>$TroubleshootingNote</api:TroubleshootingNote>
                        <api:OverrideDPSType/>`r`n
"@
	if ($Parts)
	{
		$XML += @"
						<api:Parts>
		                 		$($Parts -join "`r`n")
		               	</api:Parts>`r`n
"@
	}
	else { $XML += "<api:Parts/>`r`n" }
	
	if ($Attachments)
	{
		$XML += @"
						<api:Attachments>
		                    	$($Attachments -join "`r`n")
		               	</api:Attachments>`r`n
"@
	}
	else { $XML += "<api:Attachments/>`r`n" }
	$XML += @"
				</api:Dispatch>
	        </api:CreateDispatchRequest>
	    </api:CreateDispatch>
	</soapenv:Body>
</soapenv:Envelope>
"@
	$DellToken = Get-TDAccessToken -Dispatch
	if ($DellToken.sandbox)
	{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
	else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
	$Headers = @{
		Authorization = "Bearer $($DellToken.access_token)"
		SOAPAction    = "http://api.dell.com/IDispatchService/CreateDispatch"
	}
	
	try
	{
		$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
		$Result = $Response.Envelope.Body.CreateDispatchResponse.CreateDispatchResult.DispatchCreateResult
		####### We have to parse the XML response manually, since Powershell doesn't want to convert it to JSON natively
		$JSON = [pscustomobject]@{
			DispatchID = $Result.DispatchID
			DispatchCode = $Result.DispatchCode
			Status	   = $Result.Status
		}
		return $JSON
	}
	catch
	{
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
		$statuscode = $_.Exception.Response.StatusCode.value__
		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "$statuscode", $ErrCategory, $Null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
	}
}

function Get-DispatchStatus
{
	<#
		.SYNOPSIS
			Get the status of a dispatch
		
		.DESCRIPTION
			The primary function to track status of the work order. Failure to provide sufficient failure evidence will result in rejection of dispatches. However, there can be other reasons for rejection. 
			
			Status codes 'DSP', 'Issues' and 'QUE' indicate the WO has been approved by Dell for dispatch. A Dell dispatch number will be available for these status codes. 
			Status code 'Shipped Parts' indicates the requested part(s) has/have been dispatched. 
			Status code 'Dispatch Denied' indicates the request has been denied by Dell. Further action is required by the user on this dispatch request. They can contact Dell using phone or other means to proceed with the transaction. They can also use the
			ReSubmitDispatch() method to resubmit the request with more information. If a WO is denied more than three times, it is no longer valid and a new WO must be submitted.
		
		.PARAMETER Credentials
			Credential Object containing the Username/Password of the Technician
		
		.PARAMETER Code
			The Dispatch Code to query the status of. 
		
		.EXAMPLE
					PS C:\> Get-DispatchStatus -Code 'Value1'
		
		.NOTES
			Additional information about the function.
	#>
	
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	param
	(
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:"),
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[Alias('DispatchCode')]
		[string]$Code
	)
	
	begin
	{
		$Username = ($PSboundparameters.Credentials).getnetworkcredential().Username
		$Password = ($PSboundparameters.Credentials).getnetworkcredential().Password
		
		$DellToken = Get-TDAccessToken -Dispatch
		if ($DellToken.sandbox)
		{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
		else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
		$Headers = @{
			Authorization = "Bearer $($DellToken.access_token)"
			SOAPAction    = "http://api.dell.com/IDispatchService/GetDispatchStatus"
		}
	}
	process
	{
		
		$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
   <soapenv:Header/>
   <soapenv:Body>
      <api:GetDispatchStatus>
         <api:GetDispatchStatusRequest>
            <api:Login>$Username</api:Login>
            <api:Password>$Password</api:Password>
            <api:DispatchCode>$Code</api:DispatchCode>
         </api:GetDispatchStatusRequest>
      </api:GetDispatchStatus>
   </soapenv:Body>
</soapenv:Envelope>
"@
		
		try
		{
			$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
			$Result = $Response.Envelope.Body.GetDispatchStatusResponse.GetDispatchStatusResult.DispatchStatusResult
			####### We have to parse the XML response manually, since Powershell doesn't want to convert it to JSON natively
			$JSON = [pscustomobject]@{
				Result = $Result.Result
				Status = $Result.Status
				DPSNumber = $Result.DPSNumber
				DispatchCode = $Result.DispatchCode
				OrderDeniedReason = $Result.OrderDeniedReason
			}
			return $JSON
		}
		catch
		{
			$result = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($result)
			$reader.BaseStream.Position = 0
			$reader.DiscardBufferedData()
			$response = $reader.ReadToEnd();
			$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
			$statuscode = $_.Exception.Response.StatusCode.value__
			$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
			
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "$statuscode", $ErrCategory, $Null)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
}

function Get-PartsByServiceTag
{
	<#
		.SYNOPSIS
			Get Replaceable Parts
		
		.DESCRIPTION
			Provides the list of all replaceable parts for a particular service tag.
			Use this function to query the list of parts that can be requested for dispatch.
			
			This function should be called only once per service tag and the results should be cached at the customer system.
			
			Output of this function will be a mandatory input for 'Invoke-DispatchRequest'.
		
		.PARAMETER Credentials
			Credential Object containing the Username/Password of the Technician
		
		.PARAMETER ServiceTag
			The Service Tag to get part info for.
		
		.EXAMPLE
			PS C:\> Get-PartsByServiceTag -ServiceTag 'BR5424J'
		
		.EXAMPLE 
			PS C:\> 'BR5424J' | Get-PartsByServiceTag -Credentials $Credentials
	
	#>
	
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	[OutputType([pscustomobject])]
	param
	(
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:"),
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[Alias('SerialNumber')]
		[string]$ServiceTag
	)
	begin
	{
		$Username = ($PSboundparameters.Credentials).getnetworkcredential().Username
		$Password = ($PSboundparameters.Credentials).getnetworkcredential().Password
		
		$DellToken = Get-TDAccessToken -Dispatch
		if ($DellToken.sandbox)
		{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
		else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
		$Headers = @{
			Authorization = "Bearer $($DellToken.access_token)"
			SOAPAction    = "http://api.dell.com/IDispatchService/GetPartsbyServiceTag"
		}
	}
	process
	{
		
		$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
   	<soapenv:Header/>
   	<soapenv:Body>
		<api:GetPartsbyServiceTag>
      	<api:GetPartsbyServiceTag>
            <api:Login>$Username</api:Login>
            <api:Password>$Password</api:Password>
           	<api:ServiceTag>$ServiceTag</api:ServiceTag>
        </api:GetPartsbyServiceTag>
		</api:GetPartsbyServiceTag>
   	</soapenv:Body>
</soapenv:Envelope>
"@
		
		
		
		try
		{
			$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
			$Result = $Response.Envelope.Body.GetPartsbyServiceTagResponse.GetPartsbyServiceTagResult.PartsbyTagResult
			####### We have to parse the XML response manually, since Powershell doesn't want to convert it to JSON natively
			#Ignore these parts, they're not things that would typically be replaced in any laptop
			$PartList = $Result.Parts.PartInformation
			$Parts = @()
			foreach ($Part in $PartList)
			{
				#Create a temporary object for each part, then add it in to the array of parts
				$tmp = [pscustomobject]@{
					PartTypeCode = $Part.PartTypeCode
					PartNumber   = $part.PartNumber
					PartDescription = $Part.PartDescription
				}
				$Parts += $tmp
			}
			
			#Return to Depot isn't in the response, even though it's in the documentation
			$tmp = [pscustomobject]@{
				PartTypeCode    = "Accessory"
				PartNumber	    = "RTD"
				PartDescription = "Return to Depot"
			}
			$Parts += $tmp
			
			
			$JSON = [pscustomobject]@{
				Model = $Result.Model
				ModelDescription = $Result.ModelDescription
				Parts = $parts
			}
			
			return $JSON
		}
		catch
		{
			$result = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($result)
			$reader.BaseStream.Position = 0
			$reader.DiscardBufferedData()
			$response = $reader.ReadToEnd();
			$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
			$statuscode = $_.Exception.Response.StatusCode.value__
			switch -Wildcard ($response)
			{
				"*Missing parameters*"{ $ErrCategory = [system.management.automation.errorcategory]::InvalidArgument }
				default{ $ErrCategory = [system.management.automation.errorcategory]::InvalidOperation }
			}
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "$statuscode", $ErrCategory, $Null)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
	
}

function Get-BulkDispatch
{
	<#
		.SYNOPSIS
			Provide Status Information in Bulk
		
		.DESCRIPTION
			Provides status information for a batch of work orders
		
		.PARAMETER Credentials
			Credential Object containing the Username/Password of the Technician
		
		.PARAMETER CreatedFromDate
			Contains a date constraint to limit the result set. Work
			Orders will only be returned if they were created after this
			date.
		
		.EXAMPLE
			PS C:\> Get-Dispatches -CreatedFromDate "01/01/2019"
			
			This command will return all dispatches created since 1 January 2019 00:00.
		
		.EXAMPLE
			PS C:\> Get-Dispatches -CreatedFromDate (Get-Date).addDays(-7)
			
			This command will return all dispatches created in the last 7 days, at the current time of day.
	#>
	
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	[OutputType([pscustomobject])]
	param
	(
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:"),
		[Parameter(Mandatory = $true)]
		[datetime]$CreatedFromDate
	)
	
	$Username = ($PSboundparameters.Credentials).getnetworkcredential().Username
	$Password = ($PSboundparameters.Credentials).getnetworkcredential().Password
	
	$FormattedDate = (Get-date $CreatedFromDate -Format o)
	$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
   <soapenv:Header/>
   <soapenv:Body>
      <api:BulkDispatchesInquiry>
         <api:BulkDispatchesInquiryRequest>
            <api:Login>$Username</api:Login>
            <api:Password>$Password</api:Password>
            <api:CreatedFromDate>$FormattedDate</api:CreatedFromDate>
            <api:InStatuses></api:InStatuses>
            <api:Scope>All</api:Scope>
         </api:BulkDispatchesInquiryRequest>
      </api:BulkDispatchesInquiry>
   </soapenv:Body>
</soapenv:Envelope>
"@
	
	
	$DellToken = Get-TDAccessToken -Dispatch
	if ($DellToken.sandbox)
	{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
	else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
	$Headers = @{
		Authorization = "Bearer $($DellToken.access_token)"
		SOAPAction    = "http://api.dell.com/IDispatchService/BulkDispatchesInquiry"
	}
	
	try
	{
		$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
		$Result = $Response.Envelope.Body.BulkDispatchesInquiryResponse.BulkDispatchesInquiryResult.DispatchInquiryResult.DispatchInquiryResult
		
		$Dispatches = @()
		foreach ($Dispatch in $Result)
		{
			$tmp = [pscustomobject]@{
				Code = $Dispatch.Code
				DellDispatchNumber = $Dispatch.DellDispatchNumber
				Status = $Dispatch.Status
			}
			$Dispatches += $tmp
		}
		$Dispatches | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "Status Value" -Value $(Convert-TDStatusCode $_.status) }
		return $Dispatches
	}
	catch
	{
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
		$statuscode = $_.Exception.Response.StatusCode.value__
		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "$statuscode", $ErrCategory, $null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
	}
}

function Get-DeviceWarranty
{
	<#
		.SYNOPSIS
			Get warranty information
		
		.DESCRIPTION
			Get the warranty information for a Dell device by providing one or more service tags
		
		.PARAMETER ServiceTag
			One or more Service Tags to get Warranty information for.
			(Max. 100)
		
		.EXAMPLE
			PS C:\> Get-DeviceWarranty -ServiceTags @("B68BK79","OE6W9MA")
		
		.EXAMPLE
			PS C:\> Get-DeviceWarranty -ServiceTags "B68BK79"
		
	#>
	
	[CmdletBinding(SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateCount(0, 100)]
		[Alias('ServiceTags')]
		[array]$ServiceTag
	)
	
	Begin
	{
		try
		{ $Token = (Get-TDAccessToken -Warranty) }
		catch
		{ $PSCmdlet.ThrowTerminatingError($_) }
	}
	process
	{
		$URI = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/assets?servicetags="
		$URI = $URI + $($ServiceTag -join ",")
		
		$Invocation = New-TDInvocation $URI -Method Get -ContentType "application/json"
		try
		{
			$response = Invoke-WebRequest @invocation
			return $response
		}
		catch
		{
			$ErrorRecord = $_.Exception.Response.GetResponseStream() | Get-ErrorResult -Inv $invocation -statuscode $_.Exception.Response.StatusCode.value__
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
}

function Redo-DispatchRequest
{
	<#
		.SYNOPSIS
			Resubmit a Dispatch Request
		
		.DESCRIPTION
			If a Dispatch is denied by Dell, further action is required on this dispatch request.
			When you check the status of SR using Get-DispatchStatus and get "Dispatch Denied", you can re submit the request adding more details.
		
		.PARAMETER Credentials
			Credential Object containing Technician Username/Password
		
		.PARAMETER Code
			The Dispatch Code associated with the denied dispatch
		
		.PARAMETER TroubleshootingNote
			The troubleshooting notes for this dispatch.
			This should explain, in detail, the reason for each part request.
		
		.PARAMETER Parts
			The parts requested in this dispatch.
			Use 'Format-DispatchPart' to create the xml object for each part.
		
		.EXAMPLE
			PS C:\> Redo-DispatchRequest -DispatchCode 'SR999999999'
		
		.NOTES
			Additional information about the function.
	#>
	
	[CmdletBinding(ConfirmImpact = 'Low',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	param
	(
		[Parameter(Mandatory = $false)]
		[pscredential]$Credentials = (Get-Credential -message "Enter TechDirect Credentials:"),
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('DispatchCode')]
		[string]$Code,
		[ValidateNotNullOrEmpty()]
		[string]$TroubleshootingNote,
		[ValidateCount(1, 4)]
		[array]$Parts
	)
	
	$Username = ($PSboundparameters.Credentials).GetNetworkCredential().UserName
	$Password = ($PSboundparameters.Credentials).GetNetworkCredential().Password
	
	$XML = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://api.dell.com">
	<soapenv:Header/>
	<soapenv:Body>
		<api:ResubmitDispatch>
			<api:ResubmitDispatchRequest>
				<api:Login>$Username</api:Login>
				<api:Password>$Password</api:Password>
				<api:Dispatch>
					<api:DispatchCode>$Code</api:DispatchCode>
					<api:TroubleshootingNote>$TroubleshootingNote</api:TroubleshootingNote>
					<api:Parts>
						$Parts
					</api:Parts>
				</api:Dispatch>
			</api:ResubmitDispatchRequest>
		</api:ResubmitDispatch>
	</soapenv:Body>
</soapenv:Envelope>
"@
	
	
	$DellToken = Get-TDAccessToken -Dispatch
	if ($DellToken.sandbox)
	{ $endpoint = "https://apigtwb2cnp.us.dell.com/Sandbox/support/dispatch/v3/service" }
	else { $endpoint = "https://apigtwb2c.us.dell.com/PROD/support/dispatch/v3/service" }
	$Headers = @{
		Authorization = "Bearer $($DellToken.access_token)"
		SOAPAction    = "http://api.dell.com/IDispatchService/ResubmitDispatch"
	}
	
	try
	{
		$Response = Invoke-RestMethod $endpoint -Method Post -Body ([xml]$XML) -Headers $Headers -ContentType "text/xml"
		$Result = $Response.Envelope.Body.ResubmitDispatchResponse.ResubmitDispatchResult.DispatchCreateResult
		
		if ($Result.notes)
		{
			$ErrCategory = [system.management.automation.errorcategory]::InvalidData
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($Result.Notes.string), " ", $ErrCategory, $Null)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
		else
		{ return $Result }
	}
	catch
	{
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		$ResponseMessage = ([xml]$Response).Envelope.Body.Fault
		$statuscode = $_.Exception.Response.StatusCode.value__
		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($($ResponseMessage.faultstring), "", $ErrCategory, $Null)
		$PSCmdlet.ThrowTerminatingError($ErrorRecord)
	}
}

#region Helper Functions
function Convert-FileToBase64
{
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		$Filepath
	)
	process
	{
		$bufferSize = 9000 # should be a multiplier of 3
		$buffer = New-Object byte[] $bufferSize
		
		$reader = [System.IO.File]::OpenRead($Filepath)
		$writer = ""
		$bytesRead = 0
		do
		{
			$bytesRead = $reader.Read($buffer, 0, $bufferSize);
			$writer += ([Convert]::ToBase64String($buffer, 0, $bytesRead))
		}
		while ($bytesRead -eq $bufferSize);
		
		$reader.Dispose()
		return $writer
	}
}


function Convert-TDStatusCode
{
	<#
		.SYNOPSIS
			Convert a status code to text
		
		.DESCRIPTION
			Convert a status code to its text value. 
		
		.PARAMETER Status
			The Staus Code to convert
		
		.EXAMPLE
			PS C:\> Convert-TDStatusCode -Status 'HOLD'
		
	#>
	
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsPaging = $false,
				   SupportsShouldProcess = $false)]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[Alias('StatusCode')]
		[string]$Status
	)
	
	begin
	{
		$Codes = @{
			"Request submitted to Dell and now under review" = @(
				"2H SBD"
				"APJ Queue"
				"BIL ERROR"
				"CAR"
				"Complete Care"
				"HOLD"
				"L2 Review"
				"L2 DISPATCH"
				"NBD"
				"NON LATIN 1"
				"NPO"
				"Parts Review"
				"Pending Supervisor"
				"PND"
				"Request Submitted"
				"Request Resubmitted"
				"Returned to Depot"
				"SBD"
				"SBD4"
				"TAG/CUSTOMER MISMATCH"
			)
			"Claim Submitted"							     = @(
				"Claim Submitted"
				"Parts Returned/Claim Submitted"
			)
			"CAD Deferred"								     = @("CAD-Deferred")
			"FED Queue"									     = @("FED")
			"Moved to Claims Process"					     = "Moved_to_Claims_Process"
			"Defective Part Received"					     = "Defective Part Received"
			"Request has been denied by Dell"			     = "Dispatch Denied"
			"Request has been approved by Dell"			     = @(
				"Issued"
				"DSP"
				"ORD"
				"QUE"
			)
			"Create Dispatch/Place Request"				     = "START"
			"Pending Request 2"							     = "Pending 2"
			"Request has not been submitted to Dell"		 = "Pending Request"
			"Shipped Parts"								     = "Shipped Parts"
		}
		
	}
	
	Process
	{
		$codes.keys | % {
			if ($codes.$_ -contains "$status") { return $_ }
		}
	}
}

function Get-ErrorResult
{
	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		$Result,
		$Invocation,
		[int]$statuscode
	)
	process
	{
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();

		$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("$response", "$statuscode", $ErrCategory, $invocation)
		return $ErrorRecord
	}
}


#endregion Helper Functions
