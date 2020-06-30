<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.167
	 Created on:   	9/3/2019 8:37 AM
	 Created by:   	dz053479
	 Organization: 	CernerWorks
	 Filename:     	TechDirect.psd1
	 -------------------------------------------------------------------------
	 Module Manifest
	-------------------------------------------------------------------------
	 Module Name: TechDirect
	===========================================================================
#>


@{
	
	# Script module or binary module file associated with this manifest
	RootModule = 'TechDirect.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.0.2'
	
	# ID used to uniquely identify this module
	GUID = 'fcc2ac02-47ad-46f0-bd6b-4ec1c8ec995c'
	
	# Author of this module
	Author = 'Dakota Zinn'
	
	# Company or vendor of this module
	CompanyName = ''
	
	# Copyright statement for this module
	Copyright = '(c) 2019. All rights reserved.'
	
	# Description of the functionality provided by this module
	Description		       = @'
This Module is used to create and update SRs in Dell TechDirect.
This Module can also be used to get Warranty and Device information of one or more Service Tags.
'@
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '3.0'
	
	# Name of the Windows PowerShell host required by this module
	PowerShellHostName = ''
	
	# Minimum version of the Windows PowerShell host required by this module
	PowerShellHostVersion = ''
	
	# Minimum version of the .NET Framework required by this module
	DotNetFrameworkVersion = '2.0'
	
	# Minimum version of the common language runtime (CLR) required by this module
	CLRVersion = '2.0.50727'
	
	# Processor architecture (None, X86, Amd64, IA64) required by this module
	ProcessorArchitecture = 'None'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules = @()
	
	# Assemblies that must be loaded prior to importing this module
	RequiredAssemblies = @()
	
	# Script files (.ps1) that are run in the caller's environment prior to
	# importing this module
	ScriptsToProcess = @()
	
	# Type files (.ps1xml) to be loaded when importing this module
	TypesToProcess = @()
	
	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess = @()
	
	# Modules to import as nested modules of the module specified in
	# ModuleToProcess
	NestedModules = @()
	
	# Functions to export from this module
	FunctionsToExport = @(
		'Connect-TechDirect',
		'Get-TDAccessToken',
		'Format-DispatchPart',
		'Format-DispatchAttachment',
		'Get-TechnicianStatus',
		'Get-TechnicianInfo',
		'Invoke-DispatchRequest',
		'Get-DispatchStatus',
		'Get-PartsByServiceTag',
		'Get-BulkDispatch',
		'Get-DeviceWarranty',
		'Redo-DispatchRequest',
		'Convert-FileToBase64',
		'Convert-TDStatusCode'
	) #For performance, list functions explicitly
	
	# Cmdlets to export from this module
	CmdletsToExport = '*' 
	
	# Variables to export from this module
	VariablesToExport = '*'
	
	# Aliases to export from this module
	AliasesToExport = '*' #For performance, list alias explicitly
	
	# DSC class resources to export from this module.
	#DSCResourcesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			 Tags = @('TechDirect','Dell','Warranty','SelfDispatch')
			
			# A URL to the license for this module.
			# LicenseUri = ''
			
			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/daz96050/TechDirect'
			
			# A URL to an icon representing this module.
			IconUri = 'https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.dell.com%2Fen-us%2Fshop%2Fdell-42-whr-3-cell-primary-lithium-ion-battery%2Fapd%2F451-bcdn%2Fpc-accessories&psig=AOvVaw3Bna_LSQdll4wEERzQ3QRl&ust=1587486226656000&source=images&cd=vfe&ved=0CAIQjRxqFwoTCLDQq5m19-gCFQAAAAAdAAAAABAD'
			
			# ReleaseNotes of this module
			ReleaseNotes = @'
1. Added Project in GitHub for issues/PRs
2. Added an Icon
3. Updated Tags
'@
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}







