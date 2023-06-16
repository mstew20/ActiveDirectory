using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;

namespace EzActiveDirectory.Models;
public class UserSearchResult
{
    public ResultPropertyValueCollection Result{ get; set; }
    public bool CheckedResult { get; set; }
}
