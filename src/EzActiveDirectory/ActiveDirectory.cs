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

        public string Domain { get; private set; }
        public string LdapPath { get; private set; }

        public Action<List<UnlockUserModel>> UnlockToolAccountChecked { get; set; }
        
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

            foreach (var g in user.Properties["memberof"])
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
                de.Properties["lockOutTime"].Value = 0;
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
                    de.Properties["pwdLastSet"].Value = 0;
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
            SaveAdProperty(userPath, "accountExpires", DateTime.Now.ToFileTime().ToString());
        }
        public void ExpireAt(string userPath, DateTime date)
        {
            SaveAdProperty(userPath, "accountExpires", date.ToFileTime().ToString());
        }
        public void NeverExpires(string userPath)
        {
            SaveAdProperty(userPath, "accountExpires", "0");
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
                PropertiesToLoad(search, new[] { "badPasswordTime", "badPwdCount", "lockouttime", "adsPath" });

                SearchResult result = search.FindOne();
                DateTime? badLogonTime = DateTime.FromFileTime(result.Properties["badPasswordTime"].GetValue<long>());
                var badLogonCount = result.Properties["badPwdCount"].GetValue<int>();
                if (badLogonTime?.Year <= 1600)
                {
                    badLogonTime = null;
                }

                bool isLockedOut = result.Properties["lockouttime"].GetValue<bool>();
                if (isLockedOut || badLogonCount >= 6)
                {
                    UnlockADUser(result.Properties["adsPath"].GetValue<string>());
                    isUnlocked = true;
                }

                var server = result.Properties["adsPath"].Value().ToString().Replace(LDAP_STRING, "").Split('/')[0].Replace($".{Domain}", "");
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
                    //Filter = $"(&(objectClass=user)(objectCategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2){ filter })"
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
                sb.Append($"(givenname={ firstName }*)");

            if (!string.IsNullOrWhiteSpace(lastName))
                sb.Append($"(sn={ lastName }*)");

            if (!string.IsNullOrWhiteSpace(empId))
                sb.Append($"(employeeid={ empId }*)");

            if (!string.IsNullOrWhiteSpace(userName))
                sb.Append($"(samaccountname={ userName })");

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
                props.Add("name");
                props.Add("adspath");
                props.Add("employeeid");
                props.Add("lockouttime");
                props.Add("mail");
                props.Add("samaccountname");
                props.Add("st");
                props.Add("l");
                props.Add("physicalDeliveryOfficeName");
                props.Add("whenCreated");
                props.Add("whenChanged");
                props.Add("streetAddress");
                props.Add("Title");
                props.Add("department");
                props.Add("pwdlastset");
                props.Add("accountExpires");
                props.Add("homedirectory");
                props.Add("info");
                props.Add("userAccountControl");
                props.Add("manager");
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

                user.Path = userResults["adspath"].GetValue<string>();
                user.DisplayName = userResults["name"].GetValue<string>();
                user.EmployeeId = userResults["employeeid"].GetValue<string>();
                user.IsLockedOut = userResults["lockouttime"].GetValue<bool>();
                user.Email = userResults["mail"].GetValue<string>();
                user.UserName = userResults["samaccountname"].GetValue<string>();
                user.Notes = userResults["info"].GetValue<string>();
                user.HomeDirectory = userResults["homedirectory"].GetValue<string>();
                user.State = userResults["st"].GetValue<string>();
                user.City = userResults["l"].GetValue<string>();
                user.Office = userResults["physicalDeliveryOfficeName"].GetValue<string>();
                user.DateCreated = userResults["whenCreated"].GetValue<DateTime>();
                user.DateModified = userResults["whenChanged"].GetValue<DateTime>();
                user.StreetAddress = userResults["streetAddress"].GetValue<string>();
                user.JobTitle = userResults["Title"].GetValue<string>();
                user.Department = userResults["department"].GetValue<string>();
                user.IsExpired = IsExpired(userResults["accountExpires"].GetValue<object>());
                user.IsActive = IsActive(userResults["userAccountControl"].GetValue<object>());
                var cnManager = userResults["manager"].GetValue<string>();
                user.Manager = cnManager?.Substring(3, cnManager.IndexOf(',') - 3);

                var lastSet = DateTime.FromFileTimeUtc(userResults["pwdlastset"].GetValue<long>()).ToLocalTime();
                if (lastSet.Year <= 1600)
                {
                    user.PasswordLastSet = "";
                }
                else
                {
                    user.PasswordLastSet = $"{ lastSet:MM/dd/yyyy h:mm tt} { (PasswordNeverExpires(userResults["userAccountControl"].GetValue<object>()) ? "" : $"({ lastSet.AddDays(90).Subtract(DateTime.Now).Days })") }";
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
            var domain = LdapPath.Replace(LDAP_STRING, "")
                .Replace(DC_STRING, "")
                .Replace("/", "")
                .Replace(",", ".");
            Domain = domain;
        }
    }
}