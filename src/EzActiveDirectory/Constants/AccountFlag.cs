using System;
using System.Collections.Generic;
using System.Text;

namespace EzActiveDirectory;

public enum AccountFlag
{
    Script = 0x0001,
    Disable = 0x0002,
    HomeDirectoryRequired = 0x0008,
    Lockout = 0x0010,
    PasswordNotRequired = 0x0020,
    PasswordCantChange = 0x0040,
    AllowEncryptedTextPassword = 0x0080,
    TempDuplicateAccount = 0x0100,
    Normal = 0x0200,
    InterDomainTrust = 0x0800,
    WorkstationTrust = 0x1000,
    ServerTrust = 0x2000,
    PasswordNeverExpires = 0x10000,
    MNSLogon = 0x20000,
    SmartCardRequired = 0x40000,
    TrustedForDelegation = 0x80000,
    NotDelegated = 0x100000,
    UseDESKeyOnly = 0x200000,
    DontRequirePreAuth = 0x400000,
    PasswordExpired = 0x800000,
    TrustedToAuthForDelegation = 0x1000000,
    PartialSecrets = 0x04000000
}