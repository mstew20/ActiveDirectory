using System;
using System.Collections.Generic;
using System.Text;

namespace EzActiveDirectory;
public static class Property
{
    public const string AccountControl = "userAccountControl";
    public const string AccountExpires = "accountExpires";
    public const string Address = "streetAddress";
    public const string AdsPath = "adsPath";
    public const string BadPasswordCount = "badPwdCount";
    public const string BadPasswordTime = "badPasswordTime";
    public const string CanonicalName = "canonicalName";
    public const string Changed = "whenChanged";
    public const string City = "l";
    public const string Company = "company";
    public const string Created = "whenCreated";
    public const string Department = "department";
    public const string DirectReports = "directReports";
    public const string DisplayName = "displayName";
    public const string DistinguishedName = "distinguishedName";
    public const string EmployeeId = "employeeID";
    public const string FirstName = "givenName";
    public const string GroupMember = "memberOf";
    public const string HomeDirectory = "homeDirectory";
    public const string JobTitle = "title";
    public const string LastName = "sn";
    public const string LockOutTime = "lockoutTime";
    public const string Mail = "mail";
    public const string Manager = "manager";
    public const string MiddleName = "middleName";
    public const string Name = "name";
    public const string Notes = "info";
    public const string OfficeLocation = "physicalDeliveryOfficeName";
    public const string PasswordLastSet = "pwdLastSet";
    public const string State = "st";
    public const string Username = "sAMAccountName";
    public const string UserPrincipalName = "userPrincipalName";
    public const string PasswordExpireDate = "msDS-UserPasswordExpiryTimeComputed";
    public const string AdminDescription = "adminDescription";
    public const string ExtensionAttribute8 = "extensionAttribute8";
}
