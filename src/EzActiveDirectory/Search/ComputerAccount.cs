using EzActiveDirectory.Models;
using System.Collections.Generic;
using System.DirectoryServices;

namespace EzActiveDirectory.Search;
public class ComputerAccount
{
	private readonly ActiveDirectory _ad;

	public ComputerAccount(ActiveDirectory ad)
	{
		_ad = ad;
	}

	public Computer Find(string compName, UserCredentials credentials = null)
	{
		using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
		DirectorySearcher searcher = new(directoryEntry)
		{
			Filter = $"(&(objectClass=computer)(cn=*{compName}*))"
		};
		var result = searcher.FindOne();

		var comp = new Computer()
		{
			Name = result.Properties["name"].GetValue<string>(),
			Path = result.Properties["adspath"].GetValue<string>(),
		};

		return comp;
	}

	public List<Computer> FindAll(string compName, UserCredentials credentials = null)
	{
		using var directoryEntry = _ad.GetDirectoryEntry(_ad.LdapPath, credentials);
		DirectorySearcher searcher = new(directoryEntry)
		{
			Filter = $"(&(objectClass=computer)(cn=*{compName}*))"
		};
		var searchResult = searcher.FindAll();
		List<Computer> output = [];

		foreach (SearchResult result in searchResult)
		{
			var comp = new Computer()
			{
				Name = result.Properties["name"].GetValue<string>(),
				Path = result.Properties["adspath"].GetValue<string>(),
			};
			output.Add(comp);
		}

		return output;
	}
}
