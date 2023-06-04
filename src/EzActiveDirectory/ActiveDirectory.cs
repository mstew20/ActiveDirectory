using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

// For all AD property names visit: http://kouti.com/tables/userattributes.htm
namespace EzActiveDirectory
{
    public class ActiveDirectory
    {
        private const string LDAP_STRING = "LDAP://";
        private const string DC_STRING = "DC=";

        private UserCredentials _credentials;

        public string Domain { get; private set; }
        public string LdapPath { get; private set; }

        public event Action<List<UnlockUserModel>> UnlockToolAccountChecked;

        // Initialization
        public void Initialize(string domain = "", string ldap = "")
        {
            Domain = domain;
            LdapPath = ldap;
            if (string.IsNullOrWhiteSpace(LdapPath))
            {
                SetLdapFromDomain();
            }
            else
            {
                SetDomainFromLdap();
            }
        }
        public void ChangeDomain(string domain)
        {
            Domain = domain;
            SetLdapFromDomain();
        }
        public void ChangeLdap(string ldap)
        {
            LdapPath = ldap;
            SetDomainFromLdap();
        }
        public void ChangeCredentials(UserCredentials creds)
        {
            _credentials = creds;
        }

        //  Public AD Methods
        public List<ActiveDirectoryUser> GetUsers(string firstName, string lastName, string empId, string userName, UserCredentials credentials = null)
        {
            var users = GetUsersList(firstName, lastName, empId, $"{userName}*", credentials);
            var output = ConvertToActiveDirectoryUser(users);

            return output;
        }
        // This may need to take an object value instead of string.
        public void SaveProperty(string path, string propertyName, string value, UserCredentials credentials = null)
        {
            using DirectoryEntry user = GetDirectoryEntry(path, credentials);
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
            using DirectoryEntry user = GetDirectoryEntry(path, credentials);
            user.Properties[propertyName].Value = value;
            user.CommitChanges();
            user.Close();
        }
        public bool RemoveGroup(string userPath, string groupPath, UserCredentials credentials = null)
        {
            try
            {
                using DirectoryEntry deGroup = GetDirectoryEntry(groupPath, credentials);
                deGroup.Invoke("Remove", new object[] { userPath });
                deGroup.CommitChanges();
            }
            catch
            {
                return false;
            }

            return true;
        }
        public bool AddGroup(string userPath, string groupPath, UserCredentials credentials = null)
        {
            try
            {
                using DirectoryEntry deGroup = GetDirectoryEntry(groupPath, credentials);
                deGroup.Invoke("Add", new object[] { userPath });
                deGroup.CommitChanges();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }
        public List<ActiveDirectoryGroup> FindGroup(string groupName, UserCredentials credentials = null)
        {
            List<ActiveDirectoryGroup> groups = new();
            using DirectoryEntry de = GetDirectoryEntry(LdapPath, credentials);
            try
            {
                de.RefreshCache();
                using DirectorySearcher deSearcher = new(de);
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
        public List<ActiveDirectoryGroup> GetUserGroups(string userPath, UserCredentials credentials = null)
        {
            using var user = GetDirectoryEntry(userPath, credentials);
            List<ActiveDirectoryGroup> groups = new();
            foreach (var g in user.Properties[Property.GroupMember])
            {
                var groupPath = g.ToString();
                var groupName = groupPath.Substring(0, groupPath.IndexOf(","));
                groupName = groupName.Substring(3);
                groupPath = $"{LDAP_STRING}{groupPath}";

                ActiveDirectoryGroup group = new() { Name = groupName, Path = groupPath };
                groups.Add(group);
            }

            groups = groups.OrderBy(x => x.Name).ToList();
            return groups;
        }
        public bool UnlockUser(string path, UserCredentials credentials = null)
        {
            var output = false;

            try
            {
                using DirectoryEntry de = GetDirectoryEntry(path, credentials);
                de.Properties[Property.LockOutTime].Value = 0;
                de.CommitChanges();
                output = true;
            }
            catch (Exception)
            {
                Console.WriteLine("Error trying to unlock account!");
            }

            return output;
        }
        public void ResetPassword(string path, string password, bool passwordMustChange, UserCredentials credentials = null)
        {
            try
            {
                using DirectoryEntry de = GetDirectoryEntry(path, credentials);
                de.Invoke("SetPassword", password);

                if (passwordMustChange)
                {
                    de.Properties[Property.PasswordLastSet].Value = 0;
                }

                de.CommitChanges();
            }
            catch (Exception ex)
            {
                throw;
            }
        }
        public void ExpireNow(string userPath)
        {
            ExpireAt(userPath, DateTime.Now);
        }
        public void ExpireAt(string userPath, DateTime date)
        {
            SaveProperty(userPath, Property.AccountExpires, date.ToFileTime().ToString());
        }
        public void NeverExpires(string userPath)
        {
            ExpireAt(userPath, DateTime.FromFileTime(0));
        }

        //  Unlock Tool related methods
        public List<string> GetDomains(UserCredentials credentials = null)
        {
            using DirectoryEntry de = GetDirectoryEntry(LdapPath, credentials);
            string filter = "(&(objectCategory=computer) (| (primaryGroupID=516) (primaryGroupID=521)))";
            using DirectorySearcher searcher = new(de, filter);
            var results = searcher.FindAll();

            List<string> output = new();
            foreach (SearchResult domain in results)
            {
                StringBuilder sb = new();
                sb.Append(domain.Properties["name"].Value().ToString());
                sb.Append(".");
                sb.Append(Domain);
                output.Add(sb.ToString());
            }

            output.Sort();

            return output;
        }
        public async Task<IEnumerable<UnlockUserModel>> UnlockOnAllDomainsParallelAsync(ActiveDirectoryUser user)
        {
            List<Task> tasks = new();
            var domains = GetDomains();
            List<UnlockUserModel> output = new();

            foreach (var d in domains)
            {
                tasks.Add(Task.Run(() =>
                {
                    output.Add(CheckUserDomain(d, user.UserName));
                    UnlockToolAccountChecked?.Invoke(output);
                }));
            }

            await Task.WhenAll(tasks);
            return output;
        }
        public List<ActiveDirectoryUser> GetAllLockedUsers()
        {
            using DirectorySearcher searcher = new(GetDirectoryEntry(LdapPath))
            {
                PageSize=1000,
                SearchScope = SearchScope.Subtree,
                Filter = $"(&(objectClass=user)(objectCategory=person)(lockoutTime:1.2.840.113556.1.4.804:=4294967295)(!UserAccountControl:1.2.840.113556.1.4.803:=2)(!UserAccountControl:1.2.840.113556.1.4.803:=65536))"
            };
            PropertiesToLoad(searcher, null);

            List<Dictionary<string, ResultPropertyValueCollection>> dict = new();

            foreach (SearchResult user in searcher.FindAll())
            {
                Dictionary<string, ResultPropertyValueCollection> tempDict = new();

                foreach (var p in searcher.PropertiesToLoad)
                {
                    tempDict.Add(p, user.Properties[p]);
                }
                dict.Add(tempDict);
            }

            var users = ConvertToActiveDirectoryUser(dict);
            return users;
        }
        public UnlockUserModel CheckUserDomain(string domain, string userName, UserCredentials credentials = null)
        {
            string message = "";
            bool isUnlocked = false;
            try
            {
                using DirectoryEntry de = GetDirectoryEntry($"{LDAP_STRING}{domain}", credentials);
                var filter = SearchFilter("", "", "", userName);

                using DirectorySearcher search = new(de)
                {
                    PageSize = 1000,
                    SearchScope = SearchScope.Subtree,
                    Filter = $"(&(objectClass=user)(objectCategory=person) {filter})"
                };
                PropertiesToLoad(search, new[] { Property.BadPasswordTime, Property.BadPasswordCount, Property.LockOutTime, Property.AdsPath });

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
                    .Replace(LDAP_STRING, "")
                    .Split('/')[0]
                    .Replace($".{Domain}", "");
                message = $"{server}: {badLogonCount} Failed last on {badLogonTime?.ToLocalTime().ToString("MM/dd/yyy h:mm tt")}";
            }
            catch (Exception ex)
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

        //  Private AD Methods
        private List<Dictionary<string, ResultPropertyValueCollection>> GetUsersList(string firstName, string lastName, string empId, string userName, UserCredentials credentials = null, params string[] propertiesToLoad)
        {
            //List<ADUser> users = new List<ADUser>();
            List<Dictionary<string, ResultPropertyValueCollection>> output = new();
            using var de = GetDirectoryEntry(LdapPath, credentials);
            var filter = SearchFilter(firstName, lastName, empId, userName);

            using DirectorySearcher search = new(de)
            {
                PageSize = 1000,
                SearchScope = SearchScope.Subtree,
                Filter = $"(&(objectClass=user)(objectCategory=person) {filter})"
            };
            PropertiesToLoad(search, propertiesToLoad);

            using SearchResultCollection result = search.FindAll();
            foreach (SearchResult r in result)
            {
                Dictionary<string, ResultPropertyValueCollection> tempDict = new();

                foreach (var p in search.PropertiesToLoad)
                {
                    tempDict.Add(p, r.Properties[p]);
                }

                output.Add(tempDict);
            }


            return output;
        }
        private bool IsExpired(DateTime? date)
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
        private DateTime? GetAccountExpireDate(long fileTime)
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
        private string SearchFilter(string firstName, string lastName, string empId, string userName)
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
        private bool IsActive(object directoryObject)
        {
            int flags = (int)directoryObject;

            return !Convert.ToBoolean(flags & 0x0002);
        }
        private bool PasswordNeverExpires(object directoryObject)
        {
            int flags = (int)directoryObject;

            return Convert.ToBoolean(flags & 0x10000);
        }
        private void PropertiesToLoad(DirectorySearcher de, string[] properties)
        {
            if (properties == null || properties.Length == 0)
            {
                List<string> props = new()
                {
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
                    Property.PasswordExpireDate
                };
                de.PropertiesToLoad.AddRange(props.ToArray());
            }
            else
            {
                foreach (var p in properties)
                {
                    de.PropertiesToLoad.Add(p);
                }
            }
        }
        private List<ActiveDirectoryUser> ConvertToActiveDirectoryUser(List<Dictionary<string, ResultPropertyValueCollection>> users)
        {
            List<ActiveDirectoryUser> output = new();

            foreach (var userResults in users)
            {
                ActiveDirectoryUser user = new();

                user.Path = userResults[Property.AdsPath].GetValue<string>();
                user.CanonicalName = userResults[Property.CanonicalName].GetValue<string>();
                user.DisplayName = userResults[Property.DisplayName].GetValue<string>();
                user.FullName = userResults[Property.Name].GetValue<string>();
                user.FirstName = userResults[Property.FirstName].GetValue<string>();
                user.LastName = userResults[Property.LastName].GetValue<string>();
                user.EmployeeId = userResults[Property.EmployeeId].GetValue<string>();
                user.IsLockedOut = userResults[Property.LockOutTime].GetValue<bool>();
                user.Email = userResults[Property.Mail].GetValue<string>();
                user.UserName = userResults[Property.Username].GetValue<string>();
                user.Notes = userResults[Property.Notes].GetValue<string>();
                user.HomeDirectory = userResults[Property.HomeDirectory].GetValue<string>();
                user.State = userResults[Property.State].GetValue<string>();
                user.City = userResults[Property.City].GetValue<string>();
                user.Office = userResults[Property.OfficeLocation].GetValue<string>();
                user.DateCreated = userResults[Property.Created].GetValue<DateTime>();
                user.DateModified = userResults[Property.Changed].GetValue<DateTime>();
                user.StreetAddress = userResults[Property.Address].GetValue<string>();
                user.JobTitle = userResults[Property.JobTitle].GetValue<string>();
                user.Department = userResults[Property.Department].GetValue<string>();
                user.AccountExpireDate = GetAccountExpireDate(userResults[Property.AccountExpires].GetValue<long>());
                user.IsExpired = IsExpired(user.AccountExpireDate);
                user.IsActive = IsActive(userResults[Property.AccountControl].GetValue<object>());
                var cnManager = userResults[Property.Manager].GetValue<string>();
                user.Manager = cnManager?.Substring(3, cnManager.IndexOf(",OU") - 3).Replace("\\", "");
                user.PasswordLastSet = DateTime.FromFileTimeUtc(userResults[Property.PasswordLastSet].GetValue<long>()).ToLocalTime();
                user.PasswordNeverExpires = PasswordNeverExpires(userResults[Property.AccountControl].GetValue<object>());
                if (!user.PasswordNeverExpires)
                {
                    user.PasswordExpiryDate = userResults[Property.PasswordExpireDate].GetValue(x => DateTime.FromFileTime((long)x));
                }

                output.Add(user);
            }

            return output;
        }

        private void SetLdapFromDomain()
        {
            StringBuilder sb = new();
            sb.Append(LDAP_STRING);
            var dcs = Domain.Split('.');
            foreach (var dc in dcs)
            {
                sb.Append(DC_STRING);
                sb.Append(dc);
                sb.Append(',');
            }

            sb.Remove(sb.Length - 1, 1);
            LdapPath = sb.ToString();
        }
        private void SetDomainFromLdap()
        {
            var domain = LdapPath.Replace(LDAP_STRING, "");
            domain = domain.Remove(0, domain.IndexOf('/'))
                .Replace(DC_STRING, "")
                .Replace("/", "")
                .Replace(",", ".");
            Domain = domain;
        }
        private DirectoryEntry GetDirectoryEntry(string path, UserCredentials credentials = null)
        {
            if (credentials is not null && !(string.IsNullOrWhiteSpace(credentials.Username) && string.IsNullOrWhiteSpace(credentials.Password)))
            {
                return new(path, credentials.UsernameWithDomain, credentials.Password);
            }

            if (_credentials is not null && !(string.IsNullOrWhiteSpace(_credentials.Username) && string.IsNullOrWhiteSpace(_credentials.Password)))
            {
                return new(path, _credentials.UsernameWithDomain, _credentials.Password);
            }

            return new(path);
        }
    }
}