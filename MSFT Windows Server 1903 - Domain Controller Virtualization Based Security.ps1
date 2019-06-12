       
Configuration DSCFromGPO
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	# Module Not Found: Import-DSCResource -ModuleName 'PowerShellAccessControl'
	Node localhost
	{
	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
	 	{
	 	 	ValueName = 'EnableVirtualizationBasedSecurity'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
	 	{
	 	 	ValueName = 'RequirePlatformSecurityFeatures'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
	 	{
	 	 	ValueName = 'HypervisorEnforcedCodeIntegrity'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
	 	 	ValueData = 1

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
	 	{
	 	 	ValueName = 'HVCIMATRequired'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
	 	 	ValueData = 0

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
	 	{
	 	 	ValueName = 'LsaCfgFlags'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
	 	 	ValueData = 0

	 	}

	 	Registry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
	 	{
	 	 	ValueName = 'ConfigureSystemGuardLaunch'
	 	 	ValueType = 'Dword'
	 	 	Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
	 	 	ValueData = 1

	 	}

	}
}
DSCFromGPO -OutputPath '.\DSCConfigs'
