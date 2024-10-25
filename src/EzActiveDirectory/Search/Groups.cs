using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;

namespace EzActiveDirectory.Search;
public class Groups
{
    public static bool RemoveGroup(string userPath, string groupPath, DirectoryEntry deGroup)
    {
        try
        {
            deGroup.Invoke("Remove", new object[] { userPath });
            deGroup.CommitChanges();
        }
        catch
        {
            return false;
        }

        return true;
    }
    public static bool AddGroup(string userPath, string groupPath, DirectoryEntry deGroup)
    {
        try
        {
            deGroup.Invoke("Add", new object[] { userPath });
            deGroup.CommitChanges();
        }
        catch (Exception)
        {
            return false;
        }

        return true;
    }
    public static List<ActiveDirectoryGroup> FindGroup(string groupName, DirectoryEntry directoryEntry)
    {
        List<ActiveDirectoryGroup> groups = [];

        try
        {
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
    public static ActiveDirectoryGroup GetGroup(string groupPath, DirectoryEntry directoryEntry)
    {
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
