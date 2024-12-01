using EzActiveDirectory.Models;
using System.DirectoryServices;

namespace EzActiveDirectory.Search;
public class ComputerAccount
{
    private readonly ActiveDirectory _ad;

    public ComputerAccount(ActiveDirectory ad)
    {
        _ad = ad;
    }

    public Computer Find(string compName, UserCredentials credentials = null)
    {
        using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
        DirectorySearcher searcher = new(directoryEntry)
        {
            Filter = $"(&(objectClass=computer)(cn=*{compName}*))"
        };
        var result = searcher.FindOne();

        var comp = new Computer()
        {
            Name = result.Properties["name"].GetValue<string>(),
            Path = result.Properties["adspath"].GetValue<string>(),
        };

        return comp;
    }
}
