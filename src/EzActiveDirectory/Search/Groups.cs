using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;

namespace EzActiveDirectory.Search;
public class Groups
{
    private readonly ActiveDirectory _ad;

    public Groups(ActiveDirectory ad)
    {
        _ad = ad;
    }

    public bool RemoveUser(string userPath, string groupPath, UserCredentials credentials = null)
    {
        try
        {
            using var deGroup = _ad.GetDirectoryEntry(groupPath, credentials);
            deGroup.Invoke("Remove", new object[] { userPath });
            deGroup.CommitChanges();
        }
        catch
        {
            return false;
        }

        return true;
    }
    public bool AddUser(string userPath, string groupPath, UserCredentials credentials = null)
    {
        try
        {
            using var deGroup = _ad.GetDirectoryEntry(groupPath, credentials);
            deGroup.Invoke("Add", new object[] { userPath });
            deGroup.CommitChanges();
        }
        catch (Exception)
        {
            return false;
        }

        return true;
    }
    public List<ActiveDirectoryGroup> Find(string groupName, UserCredentials credentials = null)
    {
        List<ActiveDirectoryGroup> groups = [];

        try
        {
            using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
            directoryEntry.RefreshCache();
            using DirectorySearcher deSearcher = new(directoryEntry);
            deSearcher.Filter = $"(&(objectClass=group)(name=*{groupName}*))";
            deSearcher.SearchScope = SearchScope.Subtree;
            var results = deSearcher.FindAll();

            foreach (SearchResult group in results)
            {
                groups.Add(new()
                {
                    Path = group.Path,
                    Name = group.Properties["name"]?.Value().ToString(),
                    Description = group.Properties["description"].GetValue<string>(),
                    Notes = group.Properties["info"].GetValue<string>()
                });
            }
        }
        catch (Exception) { }

        return groups;
    }
    public ActiveDirectoryGroup Get(string groupPath, UserCredentials credentials = null)
    {
        using var directoryEntry = _ad.GetDirectoryEntry(groupPath, credentials);
        ActiveDirectoryGroup group = new()
        {
            Path = directoryEntry.Path,
            Name = directoryEntry.Properties[Property.Name].Value?.ToString(),
            Description = directoryEntry.Properties["description"].Value?.ToString(),
            Notes = directoryEntry.Properties[Property.Notes].Value?.ToString()
        };

        return group;
    }
}
