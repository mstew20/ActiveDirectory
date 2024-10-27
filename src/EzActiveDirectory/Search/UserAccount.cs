using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EzActiveDirectory.Search;
public class UserAccount
{
    private readonly ActiveDirectory _ad;

    public UserAccount(ActiveDirectory ad)
    {
        _ad = ad;
    }
    public List<ActiveDirectoryUser> GetUsers(string firstName, string lastName, string empId, string userName, UserCredentials credentials = null)
    {
        using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
        var users = GetUsers(firstName, lastName, empId, $"{userName}*", directoryEntry);
        var output = ConvertToActiveDirectoryUser(users);

        return output;
    }
    public List<ActiveDirectoryUser> GetAllLockedUsers(UserCredentials credentials = null)
    {
        using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
        using DirectorySearcher searcher = new(directoryEntry)
        {
            PageSize = 1000,
            SearchScope = SearchScope.Subtree,
            Filter = $"(&(objectClass=user)(objectCategory=person)(lockoutTime:1.2.840.113556.1.4.804:=4294967295)(!UserAccountControl:1.2.840.113556.1.4.803:={(int)AccountFlag.Disable})(!UserAccountControl:1.2.840.113556.1.4.803:={(int)AccountFlag.DontExpirePassword}))"
        };
        PropertiesToLoad(searcher, null);

        List<UserResultCollection> dict = [];

        foreach (SearchResult user in searcher.FindAll())
        {
            UserResultCollection tempDict = [];

            foreach (var p in searcher.PropertiesToLoad)
            {
                var val = new UserSearchResult { Result = user.Properties[p] };
                tempDict.Add(p, val);
            }
            dict.Add(tempDict);
        }

        var users = ConvertToActiveDirectoryUser(dict);
        return users;
    }
    public bool UnlockUser(string path, UserCredentials credentials = null)
    {
        var output = false;
        using var directoryEntry = _ad.GetDirectoryEntry(path, credentials);
        try
        {
            directoryEntry.Properties[Property.LockOutTime].Value = 0;
            directoryEntry.CommitChanges();
            output = true;
        }
        catch (Exception)
        {
            // TODO: do something with this
            Console.WriteLine("Error trying to unlock account!");
        }

        return output;
    }
    public void ResetPassword(string path, string password, bool passwordMustChange, UserCredentials credentials = null)
    {
        try
        {
            using var directoryEntry = _ad.GetDirectoryEntry(path, credentials);
            directoryEntry.Invoke("SetPassword", password);

            if (passwordMustChange)
            {
                directoryEntry.Properties[Property.PasswordLastSet].Value = 0;
            }

            directoryEntry.CommitChanges();
        }
        catch (Exception)
        {
            throw;
        }
    }
    public void ExpireAt(string userPath, DateTime date, UserCredentials credentials = null)
    {
        SaveProperty(userPath, Property.AccountExpires, date.ToFileTime().ToString(), credentials);
    }
    public void ExpireNow(string userPath, UserCredentials credentials = null)
    {
        ExpireAt(userPath, DateTime.Now, credentials);
    }
    public void NeverExpires(string userPath, UserCredentials credntials = null)
    {
        ExpireAt(userPath, DateTime.FromFileTime(0), credntials);
    }
    public List<ActiveDirectoryGroup> GetGroups(string userPath, UserCredentials credentials = null)
    {
        using var user = _ad.GetDirectoryEntry(userPath, credentials);
        List<ActiveDirectoryGroup> groups = [];
        foreach (var g in user.Properties[Property.GroupMember])
        {
            var groupPath = g.ToString();
            var groupName = groupPath[..groupPath.IndexOf(',')];
            groupName = groupName[3..];
            groupPath = $"LDAP://{groupPath}";

            ActiveDirectoryGroup group = new() { Name = groupName, Path = groupPath };
            groups.Add(group);
        }

        groups = groups.OrderBy(x => x.Name).ToList();
        return groups;
    }
    // This may need to take an object value instead of string.
    public void SaveProperty(string path, string propertyName, string value, UserCredentials credentials = null)
    {
        using var user = _ad.GetDirectoryEntry(path, credentials);
        if (string.IsNullOrWhiteSpace(value))
        {
            if (user.Properties[propertyName]?.Count > 0)
            {
                user.Properties[propertyName]?.RemoveAt(0);
            }
        }
        else
        {
            user.Properties[propertyName].Value = value;
            //user.InvokeSet(propertyName, value);
        }
        user.CommitChanges();
        user.Close();
    }
    public void SaveProperty<T>(string path, string propertyName, T value, UserCredentials credentials = null)
    {
        using var user = _ad.GetDirectoryEntry(path, credentials);
        user.Properties[propertyName].Value = value;
        user.CommitChanges();
        user.Close();
    }

    //  Unlock Tool related methods
    public async IAsyncEnumerable<UnlockUserModel> UnlockOnAllDomainsParallelAsync(ActiveDirectoryUser user, UserCredentials credentials = null)
    {
        List<Task<UnlockUserModel>> tasks = [];
        var domains = _ad.GetDomainControllers(credentials);

        foreach (var d in domains)
        {
            tasks.Add(Task.Run(() =>
            {
                return CheckUserDomain(d, user.UserName, credentials);
            }));
        }

        while (tasks.Count != 0)
        {
            var task = await Task.WhenAny(tasks);
            tasks.Remove(task);
            yield return await task;
        }
    }

    private UnlockUserModel CheckUserDomain(string domain, string userName, UserCredentials credentials)
    {
        string message = "";
        bool isUnlocked = false;
        try
        {
            using var directoryEntry = _ad.GetDirectoryEntry($"{ActiveDirectory.LDAP_STRING}{domain}", credentials);
            var filter = SearchFilter("", "", "", userName);

            using DirectorySearcher search = new(directoryEntry)
            {
                PageSize = 1000,
                SearchScope = SearchScope.Subtree,
                Filter = $"(&(objectClass=user)(objectCategory=person) {filter})"
            };
            PropertiesToLoad(search, [Property.BadPasswordTime, Property.BadPasswordCount, Property.LockOutTime, Property.AdsPath]);

            SearchResult result = search.FindOne();
            DateTime? badLogonTime = DateTime.FromFileTime(result.Properties[Property.BadPasswordTime].GetValue<long>());
            var badLogonCount = result.Properties[Property.BadPasswordCount].GetValue<int>();
            if (badLogonTime?.Year <= 1600)
            {
                badLogonTime = null;
            }

            bool isLockedOut = result.Properties[Property.LockOutTime].GetValue<bool>();
            if (isLockedOut || badLogonCount >= 6)
            {
                UnlockUser(result.Properties[Property.AdsPath].GetValue<string>());
                isUnlocked = true;
            }

            var server = result.Properties[Property.AdsPath].GetValue<string>()
                .Replace(ActiveDirectory.LDAP_STRING, "")
                .Split('/')[0]
                .Replace($".{_ad.Domain}", "");
            message = $"{server}: {badLogonCount} Failed last on {badLogonTime?.ToLocalTime().ToString("MM/dd/yyy h:mm tt")}";
        }
        catch (Exception)
        {
            message = $"Failed to connect to {domain}";
        }

        UnlockUserModel userModel = new()
        {
            Message = message,
            IsUnlocked = isUnlocked
        };

        return userModel;
    }

    private List<UserResultCollection> GetUsers(string firstName, string lastName, string empId, string userName, DirectoryEntry de, params string[] propertiesToLoad)
    {
        List<UserResultCollection> output = [];
        var filter = SearchFilter(firstName, lastName, empId, userName);

        using DirectorySearcher search = new(de)
        {
            PageSize = 1000,
            SearchScope = SearchScope.Subtree,
            Filter = $"(&(objectClass=user)(objectCategory=person) {filter})"
        };
        PropertiesToLoad(search, propertiesToLoad);

        using SearchResultCollection results = search.FindAll();
        foreach (SearchResult r in results)
        {
            UserResultCollection tempDict = [];

            foreach (var p in search.PropertiesToLoad)
            {
                var result = new UserSearchResult { Result = r.Properties[p] };
                tempDict.Add(p, result);
            }

            output.Add(tempDict);
        }


        return output;
    }
    private static List<ActiveDirectoryUser> ConvertToActiveDirectoryUser(List<UserResultCollection> users)
    {
        List<ActiveDirectoryUser> output = [];

        foreach (var userResults in users)
        {
            ActiveDirectoryUser user = new()
            {
                AccountControl = userResults.GetValue<int>(Property.AccountControl),
                Path = userResults.GetValue<string>(Property.AdsPath),
                CanonicalName = userResults.GetValue<string>(Property.CanonicalName),
                DisplayName = userResults.GetValue<string>(Property.DisplayName),
                FullName = userResults.GetValue<string>(Property.Name),
                FirstName = userResults.GetValue<string>(Property.FirstName),
                LastName = userResults.GetValue<string>(Property.LastName),
                EmployeeId = userResults.GetValue<string>(Property.EmployeeId),
                IsLockedOut = userResults.GetValue<bool>(Property.LockOutTime),
                Email = userResults.GetValue<string>(Property.Mail),
                UserName = userResults.GetValue<string>(Property.Username),
                Notes = userResults.GetValue<string>(Property.Notes),
                HomeDirectory = userResults.GetValue<string>(Property.HomeDirectory),
                State = userResults.GetValue<string>(Property.State),
                City = userResults.GetValue<string>(Property.City),
                Office = userResults.GetValue<string>(Property.OfficeLocation),
                DateCreated = userResults.GetValue<DateTime>(Property.Created),
                DateModified = userResults.GetValue<DateTime>(Property.Changed),
                StreetAddress = userResults.GetValue<string>(Property.Address),
                JobTitle = userResults.GetValue<string>(Property.JobTitle),
                Department = userResults.GetValue<string>(Property.Department),
                AccountExpireDate = GetAccountExpireDate(userResults.GetValue<long>(Property.AccountExpires)),
                PasswordLastSet = userResults.GetValue(Property.PasswordLastSet, x => DateTime.FromFileTimeUtc((long)x)).ToLocalTime()
            };
            user.IsExpired = IsExpired(user.AccountExpireDate);
            user.IsActive = IsActive(user.AccountControl);
            var cnManager = userResults.GetValue<string>(Property.Manager);
            user.Manager = cnManager?[3..cnManager.IndexOf(",OU")].Replace("\\", "");
            user.PasswordNeverExpires = PasswordNeverExpires(user.AccountControl);
            if (!user.PasswordNeverExpires)
            {
                user.PasswordExpiryDate = userResults.GetValue(Property.PasswordExpireDate, x => DateTime.FromFileTime((long)x));
            }

            user.AdditionalProperties = [];
            foreach (var item in userResults.Where(x => !x.Value.CheckedResult))
            {
                user.AdditionalProperties.Add(item.Key, item.Value.Result);
            }

            output.Add(user);
        }

        return output;
    }

    private static bool IsExpired(DateTime? date)
    {
        bool output = false;

        if (date is not null)
        {
            var today = DateTime.Now;

            if (date < today)
            {
                output = true;
            }
        }

        return output;
    }
    private static DateTime? GetAccountExpireDate(long fileTime)
    {
        DateTime? date = null;
        if (fileTime != 0 && fileTime < long.MaxValue)
        {
            date = DateTime.FromFileTime(fileTime);
            if (date?.Year == 1600)
            {
                date = DateTime.Today;
            }
        }

        return date;
    }
    private static string SearchFilter(string firstName, string lastName, string empId, string userName)
    {
        StringBuilder sb = new();

        if (!string.IsNullOrWhiteSpace(firstName))
            sb.Append($"({Property.FirstName}={firstName}*)");

        if (!string.IsNullOrWhiteSpace(lastName))
            sb.Append($"({Property.LastName}={lastName}*)");

        if (!string.IsNullOrWhiteSpace(empId))
            sb.Append($"({Property.EmployeeId}={empId}*)");

        if (!string.IsNullOrWhiteSpace(userName))
            sb.Append($"({Property.Username}={userName})");

        return sb.ToString();
    }
    private static bool IsActive(int userAccountControl)
    {
        return !CheckAccountWithFlag(userAccountControl, AccountFlag.Disable);
    }
    private static bool PasswordNeverExpires(int userAccountControl)
    {
        return CheckAccountWithFlag(userAccountControl, AccountFlag.DontExpirePassword);
    }
    private static bool CheckAccountWithFlag(int userAccountControl, AccountFlag flag)
    {
        int flags = userAccountControl;
        return Convert.ToBoolean(flags & (int)flag);
    }
    private static void PropertiesToLoad(DirectorySearcher de, string[] properties)
    {
        if (properties == null || properties.Length == 0)
        {
            string[] props =
            [
                //props.Add("distinguishedname");
                Property.DisplayName,
                    Property.CanonicalName,
                    Property.Name,
                    Property.FirstName,
                    Property.LastName,
                    Property.AdsPath,
                    Property.EmployeeId,
                    Property.LockOutTime,
                    Property.Mail,
                    Property.Username,
                    Property.State,
                    Property.City,
                    Property.OfficeLocation,
                    Property.Created,
                    Property.Changed,
                    Property.Address,
                    Property.JobTitle,
                    Property.Department,
                    Property.PasswordLastSet,
                    Property.AccountExpires,
                    Property.HomeDirectory,
                    Property.Notes,
                    Property.AccountControl,
                    Property.Manager,
                    Property.PasswordExpireDate,
                    Property.AdminDescription,
                    Property.ExtensionAttribute8
            ];
            de.PropertiesToLoad.AddRange(props);
        }
        else
        {
            foreach (var p in properties)
            {
                de.PropertiesToLoad.Add(p);
            }
        }
    }
}
