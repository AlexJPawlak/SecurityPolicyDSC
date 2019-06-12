       
Configuration DSCFromGPO
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	# Module Not Found: Import-DSCResource -ModuleName 'PowerShellAccessControl'
	Node localhost
	{
	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseEnhancedPin'
	 	{
	 	 	ValueName = 'UseEnhancedPin'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVDenyCrossOrg'
	 	{
	 	 	ValueName = 'RDVDenyCrossOrg'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
	 	 	ValueData = 0

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\DisableExternalDMAUnderLock'
	 	{
	 	 	ValueName = 'DisableExternalDMAUnderLock'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\DCSettingIndex'
	 	{
	 	 	ValueName = 'DCSettingIndex'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
	 	 	ValueData = 0

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\ACSettingIndex'
	 	{
	 	 	ValueName = 'ACSettingIndex'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
	 	 	ValueData = 0

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
	 	{
	 	 	ValueName = 'DenyDeviceClasses'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClassesRetroactive'
	 	{
	 	 	ValueName = 'DenyDeviceClassesRetroactive'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
	 	{
	 	 	ValueName = 'DenyDeviceIDs'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDsRetroactive'
	 	{
	 	 	ValueName = 'DenyDeviceIDsRetroactive'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
	 	 	ValueData = 1

	 	}

	 	<#Registry 'DELVALS_\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
	 	{
	 	 	ValueName = ''
	 	 	Exclusive = $True
	 	 	ValueData = ''
	 	 	Ensure = 'Present'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'

	 	}#>

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\1'
	 	{
	 	 	ValueName = '1'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
	 	 	ValueData = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'

	 	}

	 	<#Registry 'DELVALS_\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
	 	{
	 	 	ValueName = ''
	 	 	Exclusive = $True
	 	 	ValueData = ''
	 	 	Ensure = 'Present'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'

	 	}#>

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs\1'
	 	{
	 	 	ValueName = '1'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'
	 	 	ValueData = 'PCI\CC_0C0A'

	 	}

	 	Registry 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess'
	 	{
	 	 	ValueName = 'RDVDenyWriteAccess'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE'
	 	 	ValueData = 1

	 	}

	}
}
DSCFromGPO -OutputPath '.\DSCConfigs'
