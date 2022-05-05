using System;
using System.Collections.Generic;
using System.Text;

namespace EzActiveDirectory.Models;
public class UserCredentials
{
    public string Username { get; set; }
    public string Password { get; set; }
    public string Domain { get; set; }
    public string UsernameWithDomain
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Domain))
            {
                return Username;
            }

            return $@"{Domain}\{Username}";
        }
    }
}
