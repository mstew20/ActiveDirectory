using EzActiveDirectory.Models;
using EzActiveDirectory.Search;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;

namespace EzActiveDirectory
{
	public class ActiveDirectory
	{
		internal const string LDAP_STRING = "LDAP://";
		private const string DC_STRING = "DC=";

		private UserCredentials _credentials;

		public string Domain { get; private set; }
		public string LdapPath { get; private set; }
		public int MaxPasswordAge { get; set; }

		public UserAccount Users { get; private set; }
		public Groups Groups { get; private set; }
		public BitlockerSearch Bitlocker { get; private set; }
		public ComputerAccount Computers { get; private set; }

		public ActiveDirectory()
		{
			Users = new(this);
			Groups = new(this);
			Bitlocker = new(this);
			Computers = new(this);
		}

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
			MaxPasswordAge = 0;
		}
		public void ChangeLdap(string ldap)
		{
			LdapPath = ldap;
			SetDomainFromLdap();
			MaxPasswordAge = 0;
		}
		public void ChangeCredentials(UserCredentials creds)
		{
			_credentials = creds;
		}
		public List<string> GetDomainControllers(UserCredentials credentials = null)
		{
			string filter = "(&(objectCategory=computer) (| (primaryGroupID=516) (primaryGroupID=521)))";
			using var directoryEntry = GetDirectoryEntry(LdapPath, credentials);
			using DirectorySearcher searcher = new(directoryEntry, filter);
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
			directoryEntry.Dispose();
			output.Sort();

			return output;
		}
		internal int GetMaxPasswordAge()
		{
			using var searcher = new DirectorySearcher(GetDirectoryEntry(LdapPath));

			var results = searcher.FindOne();
			long maxDays = 0;
			var maxPwdAge = (long)results.Properties["maxPwdAge"][0];
			maxDays = maxPwdAge / -864_000_000_000;

			return (int)maxDays;
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
			if (domain.Contains('/'))
			{
				domain = domain.Remove(0, domain.IndexOf('/'));
			}
			domain = domain.Replace(DC_STRING, "")
				.Replace("/", "")
				.Replace(",", ".");
			Domain = domain;
		}
		internal DirectoryEntry GetDirectoryEntry(string path, UserCredentials credentials = null)
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