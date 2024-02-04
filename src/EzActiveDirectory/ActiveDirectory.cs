using EzActiveDirectory.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
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
			List<ActiveDirectoryGroup> groups = [];
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
		public ActiveDirectoryGroup GetGroup(string groupPath, UserCredentials credentials = null)
		{
			DirectoryEntry de = GetDirectoryEntry(groupPath, credentials);

			ActiveDirectoryGroup group = new()
			{
				Path = de.Path,
				Name = de.Properties[Property.Name].Value?.ToString(),
				Description = de.Properties["description"].Value?.ToString(),
				Notes = de.Properties[Property.Notes].Value?.ToString()
			};

			return group;
		}
		public List<ActiveDirectoryGroup> GetUserGroups(string userPath, UserCredentials credentials = null)
		{
			using var user = GetDirectoryEntry(userPath, credentials);
			List<ActiveDirectoryGroup> groups = [];
			foreach (var g in user.Properties[Property.GroupMember])
			{
				var groupPath = g.ToString();
				var groupName = groupPath[..groupPath.IndexOf(',')];
				groupName = groupName[3..];
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
			SaveProperty(userPath, Property.AccountExpires, date.ToFileTime().ToString());
		}
		public void NeverExpires(string userPath)
		{
			ExpireAt(userPath, DateTime.FromFileTime(0));
		}

		//  Bitlocker
		public List<Bitlocker> GetBitlockerByID(string keyId)
		{
			var de = GetDirectoryEntry(LdapPath);
			DirectorySearcher searcher = new(de)
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
		public List<Bitlocker> GetBitlockerByComputerName(string compName)
		{
			var de = GetDirectoryEntry(LdapPath);
			DirectorySearcher searcher = new(de)
			{
				Filter = $"(&(objectClass=computer)(cn={compName}))"
			};
			var comp = searcher.FindOne();
			var btSearch = new DirectorySearcher(de)
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

		//  Unlock Tool related methods
		public List<string> GetDomains(UserCredentials credentials = null)
		{
			using DirectoryEntry de = GetDirectoryEntry(LdapPath, credentials);
			string filter = "(&(objectCategory=computer) (| (primaryGroupID=516) (primaryGroupID=521)))";
			using DirectorySearcher searcher = new(de, filter);
			var results = searcher.FindAll();

			List<string> output = [];
			foreach (SearchResult domain in results)
			{
				StringBuilder sb = new();
				sb.Append(domain.Properties["name"].Value().ToString());
				sb.Append('.');
				sb.Append(Domain);
				output.Add(sb.ToString());
			}

			output.Sort();

			return output;
		}
		public async IAsyncEnumerable<UnlockUserModel> UnlockOnAllDomainsParallelAsync(ActiveDirectoryUser user)
		{
			List<Task<UnlockUserModel>> tasks = [];
			var domains = GetDomains();

			foreach (var d in domains)
			{
				tasks.Add(Task.Run(() =>
				{
					return CheckUserDomain(d, user.UserName);
				}));
			}

			while (tasks.Count != 0)
			{
				var task = await Task.WhenAny(tasks);
				tasks.Remove(task);
				yield return await task;
			}
		}
		public List<ActiveDirectoryUser> GetAllLockedUsers()
		{
			using DirectorySearcher searcher = new(GetDirectoryEntry(LdapPath))
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
					.Replace(LDAP_STRING, "")
					.Split('/')[0]
					.Replace($".{Domain}", "");
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

		//  Private AD Methods
		private List<UserResultCollection> GetUsersList(string firstName, string lastName, string empId, string userName, UserCredentials credentials = null, params string[] propertiesToLoad)
		{
			//List<ADUser> users = new List<ADUser>();
			List<UserResultCollection> output = [];
			using var de = GetDirectoryEntry(LdapPath, credentials);
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