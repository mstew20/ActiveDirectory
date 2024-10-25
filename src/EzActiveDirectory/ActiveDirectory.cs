using EzActiveDirectory.Models;
using EzActiveDirectory.Search;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;

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
            var directoryEntry = GetDirectoryEntry(LdapPath, credentials);
            var output = UserAccount.GetUsers(firstName, lastName, empId, userName, directoryEntry);

            return output;
        }
        // This may need to take an object value instead of string.
        public void SaveProperty(string path, string propertyName, string value, UserCredentials credentials = null)
        {
            using DirectoryEntry user = GetDirectoryEntry(path, credentials);
            UserAccount.SaveProperty(path, propertyName, value, user);
        }
        public void SaveProperty<T>(string path, string propertyName, T value, UserCredentials credentials = null)
        {
            using DirectoryEntry user = GetDirectoryEntry(path, credentials);
            UserAccount.SaveProperty<T>(path, propertyName, value, user);
        }
        public bool RemoveGroup(string userPath, string groupPath, UserCredentials credentials = null)
        {
            using DirectoryEntry deGroup = GetDirectoryEntry(groupPath, credentials);
            return Groups.RemoveGroup(userPath, groupPath, deGroup);
        }
        public bool AddGroup(string userPath, string groupPath, UserCredentials credentials = null)
        {
            using DirectoryEntry deGroup = GetDirectoryEntry(groupPath, credentials);
            return Groups.AddGroup(userPath, groupPath, deGroup);
        }
        public List<ActiveDirectoryGroup> FindGroup(string groupName, UserCredentials credentials = null)
        {
            List<ActiveDirectoryGroup> groups = [];
            using DirectoryEntry de = GetDirectoryEntry(LdapPath, credentials);
            groups = Groups.FindGroup(groupName, de);

            return groups;
        }
        public ActiveDirectoryGroup GetGroup(string groupPath, UserCredentials credentials = null)
        {
            using DirectoryEntry de = GetDirectoryEntry(groupPath, credentials);
            var group = Groups.GetGroup(groupPath, de);

            return group;
        }
        public List<ActiveDirectoryGroup> GetUserGroups(string userPath, UserCredentials credentials = null)
        {
            using var user = GetDirectoryEntry(userPath, credentials);
            var groups = UserAccount.GetGroups(userPath, user);
            return groups;
        }
        public bool UnlockUser(string path, UserCredentials credentials = null)
        {
            var output = UserAccount.UnlockUser(path, GetDirectoryEntry(path, credentials));

            return output;
        }
        public void ResetPassword(string path, string password, bool passwordMustChange, UserCredentials credentials = null)
        {
            try
            {
                UserAccount.ResetPassword(path, password, passwordMustChange, GetDirectoryEntry(path, credentials));
            }
            catch (Exception)
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
            using DirectoryEntry directoryEntry = GetDirectoryEntry(userPath);
            UserAccount.ExpireAt(userPath, date, directoryEntry);
        }
        public void NeverExpires(string userPath)
        {
            ExpireAt(userPath, DateTime.FromFileTime(0));
        }

        //  Bitlocker
        public List<Bitlocker> GetBitlockerByID(string keyId)
        {
            using var de = GetDirectoryEntry(LdapPath);
            return BitlockerSearch.GetBitlockerByID(keyId, de);
        }
        public List<Bitlocker> GetBitlockerByComputerName(string compName)
        {
            using var de = GetDirectoryEntry(LdapPath);
            return BitlockerSearch.GetBitlockerByComputerName(compName, de);
        }

        //  Unlock Tool related methods
        public async IAsyncEnumerable<UnlockUserModel> UnlockOnAllDomainsParallelAsync(ActiveDirectoryUser user)
        {
            var domainResult = UserAccount.UnlockOnAllDomainsParallelAsync(user, GetDirectoryEntry(LdapPath), Domain);
            await foreach (var result in domainResult)
            {
                yield return result;
            }
        }
        public List<ActiveDirectoryUser> GetAllLockedUsers()
        {
            var users = UserAccount.GetAllLockedUsers(GetDirectoryEntry(LdapPath));
            return users;
        }

        //  Private AD Methods
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