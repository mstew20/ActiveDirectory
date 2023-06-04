// See https://aka.ms/new-console-template for more information
using EzActiveDirectory;
using EzActiveDirectory.Models;

ActiveDirectory ad = new();
ad.Initialize("", "LDAP://dc1pinads12.global.ldap.wan/DC=global,DC=ldap,DC=wan");
var cred = new UserCredentials()
{
    Domain = "global",
    Password = "lS9{mE4+nC6",
    Username = "mstewart-sa"
};
var u = ad.GetUsers("", "", "2026897", "", cred);
Console.WriteLine(u.FirstOrDefault()?.DisplayName);
