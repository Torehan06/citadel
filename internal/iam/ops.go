package iam

// iamOps maps IAM actions to their implementations. Anything missing
// answers 501 NotImplemented.
var iamOps = map[string]opFunc{
	"CreateUser": createUser, "GetUser": getUser, "ListUsers": listUsers, "UpdateUser": updateUser, "DeleteUser": deleteUser,
	"TagUser": tagUser, "UntagUser": untagUser, "ListUserTags": listUserTags,
	"PutUserPermissionsBoundary": putUserPermissionsBoundary, "DeleteUserPermissionsBoundary": deleteUserPermissionsBoundary,

	"CreateGroup": createGroup, "GetGroup": getGroup, "ListGroups": listGroups, "UpdateGroup": updateGroup, "DeleteGroup": deleteGroup,
	"AddUserToGroup": addUserToGroup, "RemoveUserFromGroup": removeUserFromGroup, "ListGroupsForUser": listGroupsForUser,

	"CreateRole": createRole, "GetRole": getRole, "ListRoles": listRoles, "UpdateRole": updateRole, "DeleteRole": deleteRole,
	"UpdateRoleDescription": updateRoleDescription, "UpdateAssumeRolePolicy": updateAssumeRolePolicy,
	"TagRole": tagRole, "UntagRole": untagRole, "ListRoleTags": listRoleTags,
	"PutRolePermissionsBoundary": putRolePermissionsBoundary, "DeleteRolePermissionsBoundary": deleteRolePermissionsBoundary,
	"CreateServiceLinkedRole": createServiceLinkedRole, "DeleteServiceLinkedRole": deleteServiceLinkedRole,
	"GetServiceLinkedRoleDeletionStatus": getServiceLinkedRoleDeletionStatus,

	"CreatePolicy": createPolicy, "GetPolicy": getPolicy, "DeletePolicy": deletePolicy, "ListPolicies": listPolicies,
	"CreatePolicyVersion": createPolicyVersion, "GetPolicyVersion": getPolicyVersion, "ListPolicyVersions": listPolicyVersions,
	"DeletePolicyVersion": deletePolicyVersion, "SetDefaultPolicyVersion": setDefaultPolicyVersion,
	"TagPolicy": tagPolicy, "UntagPolicy": untagPolicy, "ListPolicyTags": listPolicyTags,
	"ListEntitiesForPolicy": listEntitiesForPolicy,

	"PutUserPolicy": putInlinePolicy(kUser), "GetUserPolicy": getInlinePolicy(kUser),
	"DeleteUserPolicy": deleteInlinePolicy(kUser), "ListUserPolicies": listInlinePolicies(kUser),
	"PutGroupPolicy": putInlinePolicy(kGroup), "GetGroupPolicy": getInlinePolicy(kGroup),
	"DeleteGroupPolicy": deleteInlinePolicy(kGroup), "ListGroupPolicies": listInlinePolicies(kGroup),
	"PutRolePolicy": putInlinePolicy(kRole), "GetRolePolicy": getInlinePolicy(kRole),
	"DeleteRolePolicy": deleteInlinePolicy(kRole), "ListRolePolicies": listInlinePolicies(kRole),
	"AttachUserPolicy": attachPolicy(kUser), "DetachUserPolicy": detachPolicy(kUser), "ListAttachedUserPolicies": listAttachedPolicies(kUser),
	"AttachGroupPolicy": attachPolicy(kGroup), "DetachGroupPolicy": detachPolicy(kGroup), "ListAttachedGroupPolicies": listAttachedPolicies(kGroup),
	"AttachRolePolicy": attachPolicy(kRole), "DetachRolePolicy": detachPolicy(kRole), "ListAttachedRolePolicies": listAttachedPolicies(kRole),

	"CreateAccessKey": createAccessKey, "ListAccessKeys": listAccessKeys, "UpdateAccessKey": updateAccessKey,
	"DeleteAccessKey": deleteAccessKey, "GetAccessKeyLastUsed": getAccessKeyLastUsed,
	"CreateLoginProfile": createLoginProfile, "GetLoginProfile": getLoginProfile,
	"UpdateLoginProfile": updateLoginProfile, "DeleteLoginProfile": deleteLoginProfile,
	"UploadSSHPublicKey": uploadSSHPublicKey, "GetSSHPublicKey": getSSHPublicKey, "ListSSHPublicKeys": listSSHPublicKeys,
	"UpdateSSHPublicKey": updateSSHPublicKey, "DeleteSSHPublicKey": deleteSSHPublicKey,
	"UploadSigningCertificate": uploadSigningCertificate, "ListSigningCertificates": listSigningCertificates,
	"UpdateSigningCertificate": updateSigningCertificate, "DeleteSigningCertificate": deleteSigningCertificate,
	"CreateVirtualMFADevice": createVirtualMFADevice, "DeleteVirtualMFADevice": deleteVirtualMFADevice,
	"ListVirtualMFADevices": listVirtualMFADevices, "EnableMFADevice": enableMFADevice,
	"DeactivateMFADevice": deactivateMFADevice, "ListMFADevices": listMFADevices,

	"CreateInstanceProfile": createInstanceProfile, "GetInstanceProfile": getInstanceProfile,
	"DeleteInstanceProfile": deleteInstanceProfile, "ListInstanceProfiles": listInstanceProfiles,
	"ListInstanceProfilesForRole": listInstanceProfilesForRole, "AddRoleToInstanceProfile": addRoleToInstanceProfile,
	"RemoveRoleFromInstanceProfile": removeRoleFromInstanceProfile, "TagInstanceProfile": tagInstanceProfile,
	"UntagInstanceProfile": untagInstanceProfile, "ListInstanceProfileTags": listInstanceProfileTags,

	"CreateSAMLProvider": createSAMLProvider, "GetSAMLProvider": getSAMLProvider, "UpdateSAMLProvider": updateSAMLProvider,
	"DeleteSAMLProvider": deleteSAMLProvider, "ListSAMLProviders": listSAMLProviders,
	"CreateOpenIDConnectProvider": createOpenIDConnectProvider, "GetOpenIDConnectProvider": getOpenIDConnectProvider,
	"DeleteOpenIDConnectProvider": deleteOpenIDConnectProvider, "ListOpenIDConnectProviders": listOpenIDConnectProviders,
	"UpdateOpenIDConnectProviderThumbprint": updateOpenIDConnectProviderThumbprint,

	"UpdateAccountPasswordPolicy": updateAccountPasswordPolicy, "GetAccountPasswordPolicy": getAccountPasswordPolicy,
	"DeleteAccountPasswordPolicy": deleteAccountPasswordPolicy, "GetAccountSummary": getAccountSummary,
	"CreateAccountAlias": createAccountAlias, "DeleteAccountAlias": deleteAccountAlias, "ListAccountAliases": listAccountAliases,
	"GenerateCredentialReport": generateCredentialReport, "GetCredentialReport": getCredentialReport,
	"GetAccountAuthorizationDetails": getAccountAuthorizationDetails,
	"UploadServerCertificate":        uploadServerCertificate, "GetServerCertificate": getServerCertificate,
	"DeleteServerCertificate": deleteServerCertificate, "ListServerCertificates": listServerCertificates,
}
