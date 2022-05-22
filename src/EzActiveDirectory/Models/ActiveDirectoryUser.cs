using System;

namespace EzActiveDirectory.Models
{
    public class ActiveDirectoryUser
    {
        public string Email { get; set; }
        public string UserName { get; set; }
        public string DisplayName { get; set; }
        public string FullName { get; set; }
        public string Path { get; set; }
        public bool IsLockedOut { get; set; }
        public string EmployeeId { get; set; }
        public DateTime PasswordLastSet { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DateModified { get; set; }
        public DateTime PasswordExpiryDate { get; set; }
        public DateTime? AccountExpireDate { get; set; }
        public bool IsExpired { get; set; }
        public string State { get; set; }
        public string City { get; set; }
        public string Office { get; set; }
        public string StreetAddress { get; set; }
        public string JobTitle { get; set; }
        public string Department { get; set; }
        public string HomeDirectory { get; set; }
        public string Location
        {
            get
            {
                if (string.IsNullOrEmpty(City))
                {
                    return Office;
                }

                return $"{ Office } - { City }, { State }";
            }
        }
        public string Notes { get; set; }
        public string Manager { get; set; }
        public bool IsActive { get; set; }
        public bool PasswordNeverExpires { get; set; }
    }
}
