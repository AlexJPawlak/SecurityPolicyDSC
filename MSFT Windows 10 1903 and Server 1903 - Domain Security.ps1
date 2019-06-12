       
Configuration DSCFromGPO
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	# Module Not Found: Import-DSCResource -ModuleName 'PowerShellAccessControl'
	Node localhost
	{
	 	AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
	 	{
	 	 	Reset_account_lockout_counter_after = 15
	 	 	Name = 'Reset_account_lockout_counter_after'

	 	}

	 	AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
	 	{
	 	 	Name = 'Account_lockout_threshold'
	 	 	Account_lockout_threshold = 10

	 	}

	 	AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
	 	{
	 	 	Name = 'Password_must_meet_complexity_requirements'
	 	 	Password_must_meet_complexity_requirements = 'Enabled'

	 	}

	 	AccountPolicy 'SecuritySetting(INF): LockoutDuration'
	 	{
	 	 	Name = 'Account_lockout_duration'
	 	 	Account_lockout_duration = 15

	 	}

	 	AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
	 	{
	 	 	Name = 'Enforce_password_history'
	 	 	Enforce_password_history = 24

	 	}

	 	AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
	 	{
	 	 	Name = 'Store_passwords_using_reversible_encryption'
	 	 	Store_passwords_using_reversible_encryption = 'Disabled'

	 	}

	 	AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
	 	{
	 	 	Name = 'Minimum_Password_Length'
	 	 	Minimum_Password_Length = 14

	 	}

	}
}
DSCFromGPO -OutputPath '.\DSCConfigs'
