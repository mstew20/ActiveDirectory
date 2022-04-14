using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// For all AD property names visit: http://kouti.com/tables/userattributes.htm
namespace EzActiveDirectory
{
    public class ActiveDirectory
    {
        private const string LDAP_STRING = "LDAP://";
        private const string DC_STRING = "DC=";

        private const string DISTINGUISHED_NAME_PROPERTY = "distinguishedName";
        private const string FIRSTNAME_PROPERTY = "givenName";
        private const string LASTNAME_PROPERTY = "sn";
        private const string DISPLAYNAME_PROPERTY = "displayName";
        private const string NAME_PROPERTY = "name";
        private const string ADSPATH_PROPERTY = "adsPath";
        private const string EMPLOYEEID_PROPERTY = "employeeID";
        private const string LOCKOUTTIME_PROPERTY = "lockoutTime";
        private const string MAIL_PROPERTY = "mail";
        private const string USERNAME_PROPERTY = "sAMAccountName";
        private const string STATE_PROPERTY = "st";
        private const string CITY_PROPERTY = "l";
        private const string OFFICE_LOCATION_PROPERTY = "physicalDeliveryOfficeName";
        private const string CREATED_PROPERTY = "whenCreated";
        private const string CHANGED_PROPERTY = "whenChanged";
        private const string ADDRESS_PROPERTY = "streetAddress";
        private const string JOB_TITLE_PROPERTY = "title";
        private const string DEPARTMENT_PROPERTY = "department";
        private const string PASSWORD_LAST_SET_PROPERTY = "pwdLastSet";
        private const string ACCOUNT_EXPIRES_PROPERTY = "accountExpires";
        private const string HOME_DIRECTORY_PROPERTY = "homeDirectory";
        private const string NOTES_PROPERTY = "info";
        private const string ACCOUNT_CONTROL_PROPERTY = "userAccountControl";
        private const string MANAGER_PROPERTY = "manager";
        private const string DIRECT_REPORTS_PROPERTY = "directReports";
        private const string COMPANY_PROPERTY = "company";
        private const string USER_PRINCIPAL_NAME_PROPERTY = "userPrincipalName";
        private const string MIDDLE_NAME_PROPERTY = "middleName";
        private const string GROUP_MEMBER_PROPERTY = "memberOf";
        private const string BAD_PASSWORD_TIME_PROPERTY = "badPasswordTime";
        private const string BAD_PASSOWRD_COUNT_PROPERTY = "badPwdCount";


        public string Domain { get; private set; }
        public string LdapPath { get; private set; }

        public event Action<List<UnlockUserModel>> UnlockToolAccountChecked;

        // Initialization
        public void Initialize(string domain = "", string ldap = "")
        {
            Domain = domain;
            LdapPath = ldap;
            SetLdapFromDomain();
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

        //  Public AD Methods
        public List<ActiveDirectoryUser> GetADUsers(string firstName, string lastName, string empId, string userName)
        {
            var users = GetADUsersList(firstName, lastName, empId, $"{ userName }*");
            var output = ConvertToAdUser(users);

            return output;
        }
        // This may need to take an object value instead of string.
        public void SaveAdProperty(string path, string propertyName, string value)
        {
            using DirectoryEntry user = new(path);
            if (string.IsNullOrWhiteSpace(value))
            {
                user.Properties[propertyName]?.RemoveAt(0);
            }
            else
            {
                user.Properties[propertyName].Value = value;
                //user.InvokeSet(propertyName, value);
            }
            user.CommitChanges();
            user.Close();
        }
        public bool RemoveGroup(string userPath, string groupPath)
        {
            using DirectoryEntry user = new(userPath);
            try
            {
                using DirectoryEntry deGroup = new(groupPath, null, null);
                deGroup.Invoke("Remove", new object[] { userPath });
                deGroup.CommitChanges();
            }
            catch
            {
                return false;
            }

            return true;
        }
        public bool AddGroup(string userPath, string groupPath)
        {
            try
            {
                using DirectoryEntry deGroup = new(groupPath, null, null);
                deGroup.Invoke("Add", new object[] { userPath });
                deGroup.CommitChanges();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }
        public List<ActiveDirectoryGroup> FindGroup(string groupName)
        {
            List<ActiveDirectoryGroup> groups = new();
            using DirectoryEntry de = new(LdapPath);
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
                        Name = group.Properties["name"]?.Value().ToString()
                    });
                }
            }
            catch (Exception) { }

            return groups;
        }
        public List<ActiveDirectoryGroup> GetUserGroups(string userPath)
        {
            using DirectoryEntry user = new(userPath);
            List<ActiveDirectoryGroup> groups = new();

            foreach (var g in user.Properties[GROUP_MEMBER_PROPERTY])
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
        public bool UnlockADUser(string path)
        {
            var output = false;

            try
            {
                using DirectoryEntry de = new(path);
                de.Properties[LOCKOUTTIME_PROPERTY].Value = 0;
                de.CommitChanges();
                output = true;
            }
            catch (Exception)
            {
                Console.WriteLine("Error trying to unlock account!");
            }

            return output;
        }
        public void ResetPassword(string path, string password, bool passwordMustChange)
        {
            try
            {
                using DirectoryEntry de = new(path);
                de.Invoke("SetPassword", password);

                if (passwordMustChange)
                {
                    de.Properties[PASSWORD_LAST_SET_PROPERTY].Value = 0;
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
            SaveAdProperty(userPath, ACCOUNT_EXPIRES_PROPERTY, date.ToFileTime().ToString());
        }
        public void NeverExpires(string userPath)
        {
            ExpireAt(userPath, DateTime.FromFileTime(0));
        }

        //  Unlock Tool related methods
        public List<string> GetDomains()
        {
            using DirectoryEntry de = new(LdapPath);
            string filter = "(&(objectCategory=computer) (| (primaryGroupID=516) (primaryGroupID=521)))";
            using DirectorySearcher searcher = new(de, filter);
            var results = searcher.FindAll();

            List<string> output = new();
            foreach (SearchResult domain in results)
            {
                output.Add(domain.Properties["name"].Value().ToString());
            }

            output.Sort();

            return output;
        }
        public async Task<IEnumerable<UnlockUserModel>> ADUnlockToolParallelAsync(ActiveDirectoryUser user)
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
        public List<string> GetAllLockedUsers()
        {
            ProcessStartInfo processStartInfo = new()
            {
                FileName = "powershell.exe",
                Arguments = "& Search-ADAccount -LockedOut | Select Name",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process p = new();
            p.StartInfo = processStartInfo;
            p.Start();
            var res = p.StandardOutput.ReadToEnd();
            var usersResponse = res.Split(new string[] { "\n" }, StringSplitOptions.RemoveEmptyEntries).ToList();
            usersResponse.RemoveRange(0, 3);
            usersResponse.RemoveRange(usersResponse.Count - 2, 2);

            List<string> output = new();
            foreach (var x in usersResponse)
            {
                var r = x.Trim();
                output.Add(r);
            }

            return output;
        }
        public UnlockUserModel CheckUserDomain(string domain, string userName)
        {
            string message = "";
            bool isUnlocked = false;
            try
            {
                using DirectoryEntry de = new($"{LDAP_STRING}{domain}");
                var filter = SearchFilter("", "", "", userName);

                using DirectorySearcher search = new(de)
                {
                    PageSize = 1000,
                    SearchScope = SearchScope.Subtree,
                    Filter = $"(&(objectClass=user)(objectCategory=person) { filter })"
                };
                PropertiesToLoad(search, new[] { BAD_PASSWORD_TIME_PROPERTY, BAD_PASSOWRD_COUNT_PROPERTY, LOCKOUTTIME_PROPERTY, ADSPATH_PROPERTY });

                SearchResult result = search.FindOne();
                DateTime? badLogonTime = DateTime.FromFileTime(result.Properties[BAD_PASSWORD_TIME_PROPERTY].GetValue<long>());
                var badLogonCount = result.Properties[BAD_PASSOWRD_COUNT_PROPERTY].GetValue<int>();
                if (badLogonTime?.Year <= 1600)
                {
                    badLogonTime = null;
                }

                bool isLockedOut = result.Properties[LOCKOUTTIME_PROPERTY].GetValue<bool>();
                if (isLockedOut || badLogonCount >= 6)
                {
                    UnlockADUser(result.Properties[ADSPATH_PROPERTY].GetValue<string>());
                    isUnlocked = true;
                }

                var server = result.Properties[ADSPATH_PROPERTY].GetValue<string>()
                    .Replace(LDAP_STRING, "")
                    .Split('/')[0]
                    .Replace($".{Domain}", "");
                message = $"{ server }: { badLogonCount } Failed last on { badLogonTime?.ToLocalTime().ToString("MM/dd/yyy h:mm tt") }";
            }
            catch (Exception ex)
            {
                message = $"Failed to connect to { domain }";
            }

            UnlockUserModel userModel = new()
            {
                Message = message,
                IsUnlocked = isUnlocked
            };

            return userModel;
        }

        //  Private AD Methods
        private List<Dictionary<string, ResultPropertyValueCollection>> GetADUsersList(string firstName, string lastName, string empId, string userName, params string[] propertiesToLoad)
        {
            //List<ADUser> users = new List<ADUser>();
            List<Dictionary<string, ResultPropertyValueCollection>> output = new();
            using (DirectoryEntry de = new(LdapPath))
            {
                var filter = SearchFilter(firstName, lastName, empId, userName);

                using DirectorySearcher search = new(de)
                {
                    PageSize = 1000,
                    SearchScope = SearchScope.Subtree,
                    Filter = $"(&(objectClass=user)(objectCategory=person) { filter })"
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
            }

            return output;
        }
        private bool IsExpired(object value)
        {
            bool output = false;

            if (Convert.ToBoolean(value))
            {
                try
                {
                    var date = DateTime.FromFileTime((long)value);
                    var today = DateTime.Now;

                    if (date < today)
                    {
                        output = true;
                    }
                }
                catch (Exception) { }
            }

            return output;
        }
        private string SearchFilter(string firstName, string lastName, string empId, string userName)
        {
            StringBuilder sb = new();

            if (!string.IsNullOrWhiteSpace(firstName))
                sb.Append($"({FIRSTNAME_PROPERTY}={ firstName }*)");

            if (!string.IsNullOrWhiteSpace(lastName))
                sb.Append($"({LASTNAME_PROPERTY}={ lastName }*)");

            if (!string.IsNullOrWhiteSpace(empId))
                sb.Append($"({EMPLOYEEID_PROPERTY}={ empId }*)");

            if (!string.IsNullOrWhiteSpace(userName))
                sb.Append($"({USERNAME_PROPERTY}={ userName })");

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
                List<string> props = new();
                //props.Add("distinguishedname");
                props.Add(DISPLAYNAME_PROPERTY);
                props.Add(NAME_PROPERTY);
                props.Add(ADSPATH_PROPERTY);
                props.Add(EMPLOYEEID_PROPERTY);
                props.Add(LOCKOUTTIME_PROPERTY);
                props.Add(MAIL_PROPERTY);
                props.Add(USERNAME_PROPERTY);
                props.Add(STATE_PROPERTY);
                props.Add(CITY_PROPERTY);
                props.Add(OFFICE_LOCATION_PROPERTY);
                props.Add(CREATED_PROPERTY);
                props.Add(CHANGED_PROPERTY);
                props.Add(ADDRESS_PROPERTY);
                props.Add(JOB_TITLE_PROPERTY);
                props.Add(DEPARTMENT_PROPERTY);
                props.Add(PASSWORD_LAST_SET_PROPERTY);
                props.Add(ACCOUNT_EXPIRES_PROPERTY);
                props.Add(HOME_DIRECTORY_PROPERTY);
                props.Add(NOTES_PROPERTY);
                props.Add(ACCOUNT_CONTROL_PROPERTY);
                props.Add(MANAGER_PROPERTY);
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
        private List<ActiveDirectoryUser> ConvertToAdUser(List<Dictionary<string, ResultPropertyValueCollection>> users)
        {
            List<ActiveDirectoryUser> output = new();

            foreach (var userResults in users)
            {
                ActiveDirectoryUser user = new();

                user.Path = userResults[ADSPATH_PROPERTY].GetValue<string>();
                user.DisplayName = userResults[DISPLAYNAME_PROPERTY].GetValue<string>();
                user.FullName = userResults[NAME_PROPERTY].GetValue<string>();
                user.EmployeeId = userResults[EMPLOYEEID_PROPERTY].GetValue<string>();
                user.IsLockedOut = userResults[LOCKOUTTIME_PROPERTY].GetValue<bool>();
                user.Email = userResults[MAIL_PROPERTY].GetValue<string>();
                user.UserName = userResults[USERNAME_PROPERTY].GetValue<string>();
                user.Notes = userResults[NOTES_PROPERTY].GetValue<string>();
                user.HomeDirectory = userResults[HOME_DIRECTORY_PROPERTY].GetValue<string>();
                user.State = userResults[STATE_PROPERTY].GetValue<string>();
                user.City = userResults[CITY_PROPERTY].GetValue<string>();
                user.Office = userResults[OFFICE_LOCATION_PROPERTY].GetValue<string>();
                user.DateCreated = userResults[CREATED_PROPERTY].GetValue<DateTime>();
                user.DateModified = userResults[CHANGED_PROPERTY].GetValue<DateTime>();
                user.StreetAddress = userResults[ADDRESS_PROPERTY].GetValue<string>();
                user.JobTitle = userResults[JOB_TITLE_PROPERTY].GetValue<string>();
                user.Department = userResults[DEPARTMENT_PROPERTY].GetValue<string>();
                user.IsExpired = IsExpired(userResults[ACCOUNT_EXPIRES_PROPERTY].GetValue<object>());
                user.IsActive = IsActive(userResults[ACCOUNT_CONTROL_PROPERTY].GetValue<object>());
                var cnManager = userResults[MANAGER_PROPERTY].GetValue<string>();
                user.Manager = cnManager?.Substring(3, cnManager.IndexOf(',') - 3);
                user.PasswordLastSet = DateTime.FromFileTimeUtc(userResults[PASSWORD_LAST_SET_PROPERTY].GetValue<long>()).ToLocalTime();
                user.PasswordNeverExpires = PasswordNeverExpires(userResults[ACCOUNT_CONTROL_PROPERTY].GetValue<object>());

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
            var domain = LdapPath.Replace(LDAP_STRING, "")
                .Replace(DC_STRING, "")
                .Replace("/", "")
                .Replace(",", ".");
            Domain = domain;
        }
    }
}