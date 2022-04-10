using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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
            catch (PasswordException ex)
            {
                throw new PasswordException(ex.Message);
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
        public IEnumerable<UnlockUserModel> ADUnlockTool(ActiveDirectoryUser user)
        {
            var domains = GetDomains();

            foreach (var d in domains)
            {
                using PrincipalContext context = new(ContextType.Domain, d);
                using var dUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, user.UserName);
                UnlockUserModel userModel = new();
                if (dUser.IsAccountLockedOut())
                {
                    dUser.UnlockAccount();
                    userModel.IsUnlocked = true;
                }

                userModel.Message = $"{ d.Substring(0, d.IndexOf(".")) }: { dUser.BadLogonCount } Failed last on { dUser.LastBadPasswordAttempt?.ToLocalTime().ToString("MM/dd/yyy h:mm tt") }";
                yield return userModel;
            }
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
                    try
                    {
                        output.Add(CheckUserDomain(d, user.UserName));
                    }
                    catch (Exception)
                    {
                        output.Add(new UnlockUserModel { Message = $"Failed to connect to { d }" });
                    }
                    finally
                    {
                        UnlockToolAccountChecked?.Invoke(output);
                    }
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
            using PrincipalContext context = new(ContextType.Domain, domain);
            using var dUser = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, userName);
            UnlockUserModel userModel = new();

            if (dUser.IsAccountLockedOut() || dUser.BadLogonCount >= 6)
            {
                dUser.UnlockAccount();
                userModel.IsUnlocked = true;
            }

            var server = dUser.Context.ConnectedServer.Substring(0, domain.IndexOf("."));
            userModel.Message = $"{ server }: { dUser.BadLogonCount } Failed last on { dUser.LastBadPasswordAttempt?.ToLocalTime().ToString("MM/dd/yyy h:mm tt") }";

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
                        tempDict.Add(p.ToString(), r.Properties[p.ToString()]);
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
            List<ActiveDirectoryUser> adUsers = new();

            foreach (var u in users)
            {
                ActiveDirectoryUser user = new();

                user.Path = u["adspath"].Value()?.ToString();
                user.DisplayName = u["name"].Value()?.ToString();
                user.EmployeeId = u["employeeid"].Value()?.ToString();
                var s = u["lockouttime"].Value();
                user.IsLockedOut = Convert.ToBoolean(s);
                user.Email = u["mail"].Value()?.ToString();
                user.UserName = u["samaccountname"].Value()?.ToString();
                user.Notes = u["info"].Value()?.ToString();
                user.HomeDirectory = u["homedirectory"].Value()?.ToString();
                user.State = u["st"].Value()?.ToString();
                user.City = u["l"].Value()?.ToString();
                user.Office = u["physicalDeliveryOfficeName"].Value()?.ToString();
                user.DateCreated = (DateTime)u["whenCreated"].Value();
                user.DateModified = (DateTime)u["whenChanged"].Value();
                user.StreetAddress = u["streetAddress"].Value()?.ToString();
                user.JobTitle = u["Title"].Value()?.ToString();
                user.Department = u["department"].Value()?.ToString();
                user.IsExpired = IsExpired(u["accountExpires"].Value());
                var lastSet = DateTime.FromFileTimeUtc((long)u["pwdlastset"].Value()).ToLocalTime();
                user.IsActive = IsActive(u["userAccountControl"].Value());
                var cnManager = u["manager"].Value()?.ToString();
                user.Manager = cnManager?.Substring(3, cnManager.IndexOf(',') - 3);

                if (lastSet.Year == 1600)
                {
                    user.PasswordLastSet = "";
                }
                else
                {
                    user.PasswordLastSet = $"{ lastSet:MM/dd/yyyy h:mm tt} { (PasswordNeverExpires(u["userAccountControl"].Value()) ? "" : $"({ lastSet.AddDays(90).Subtract(DateTime.Now).Days })") }";
                }

                adUsers.Add(user);
            }

            return adUsers;
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