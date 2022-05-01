using System;
using System.Collections.Generic;
using System.Text;

namespace EzActiveDirectory;
public static class AccountFlags
{
    public const int Active = 0x0002;
    public const int PasswordNeverExpires = 0x10000;
}
