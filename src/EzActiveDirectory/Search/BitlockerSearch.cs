using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;

namespace EzActiveDirectory.Search;
public class BitlockerSearch
{
    private readonly ActiveDirectory _ad;

    public BitlockerSearch(ActiveDirectory ad)
    {
        _ad = ad;
    }

    public List<Bitlocker> GetByID(string keyId, UserCredentials credentials = null)
    {
        using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
        DirectorySearcher searcher = new(directoryEntry)
        {
            SearchScope = SearchScope.Subtree,
            Filter = $"(&(objectClass=msFVE-RecoveryInformation)(name=*{keyId}*))"
        };
        searcher.PropertiesToLoad.AddRange(["msfve-recoverypassword", "msfve-recoveryguid", "distinguishedname", "whencreated"]);

        List<Bitlocker> output = new();
        foreach (SearchResult item in searcher.FindAll())
        {
            var key = item.Properties["msfve-recoverypassword"].GetValue<string>();
            var id = item.Properties["msfve-recoveryguid"].GetValue<byte[]>();
            var date = item.Properties["whencreated"].GetValue<DateTime>();
            var computerOU = item.Properties["distinguishedname"].GetValue<string>();
            Bitlocker bt = new(key, id);
            bt.ComputerName = computerOU.Split(',')[1].Remove(0, 3);
            bt.Date = date;

            output.Add(bt);
        }

        return output;
    }
    public List<Bitlocker> GetByComputerName(string compName, UserCredentials credentials = null)
    {
        using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
        DirectorySearcher searcher = new(directoryEntry)
        {
            Filter = $"(&(objectClass=computer)(cn={compName}))"
        };
        var comp = searcher.FindOne();
        var btSearch = new DirectorySearcher(directoryEntry)
        {
            SearchRoot = comp.GetDirectoryEntry(),
            SearchScope = SearchScope.Subtree,
            Filter = "(&(objectClass=msFVE-RecoveryInformation))"
        };
        searcher.PropertiesToLoad.AddRange(["msfve-recoverypassword", "msfve-recoveryguid", "distinguishedname", "whencreated"]);

        List<Bitlocker> output = new();
        foreach (SearchResult item in btSearch.FindAll())
        {
            var key = item.Properties["msfve-recoverypassword"].GetValue<string>();
            var id = item.Properties["msfve-recoveryguid"].GetValue<byte[]>();
            var date = item.Properties["whencreated"].GetValue<DateTime>();
            var computerOU = item.Properties["distinguishedname"].GetValue<string>();
            Bitlocker bt = new(key, id);
            bt.ComputerName = computerOU.Split(',')[1].Remove(0, 3);
            bt.Date = date;

            output.Add(bt);
        }

        return output;
    }
}
