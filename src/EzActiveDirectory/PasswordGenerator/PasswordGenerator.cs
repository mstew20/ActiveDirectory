using System;
using System.Collections.Generic;
using System.Text;

namespace EzActiveDirectory.PasswordGenerator
{
    public class PasswordGenerator
    {
        private static string GetChars()
        {
            List<char> chars = new();

            for (char i = '0'; i < '9'; i++)
            {
                chars.Add(i);
            }

            for (char i = 'A'; i < 'Z'; i++)
            {
                chars.Add(i);
            }

            for (char i = 'a'; i < 'z'; i++)
            {
                chars.Add(i);
            }

            return new string(chars.ToArray());
        }

        private static string GenPassword(string chars, int len)
        {
            StringBuilder sb = new();
            var rand = new Random();
            for (int i = 0; i < len; i++)
            {
                sb.Append(chars[rand.Next(chars.Length)]);
            }

            return sb.ToString();
        }

        public static string GeneratePassword(int length)
        {
            var chars = GetChars();
            bool hasNumber = false;
            bool hasCapital = false; ;
            string password = string.Empty;
            while (hasNumber == false || hasCapital == false)
            {
                password = GenPassword(chars, length);
                hasNumber = HasNumber(password);
                hasCapital = HasCapital(password);
            }

            return password;
        }

        private static bool HasNumber(string password)
        {
            foreach (var c in password)
            {
                if (int.TryParse(c.ToString(), out _))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasCapital(string password)
        {
            foreach (var c in password)
            {
                if (c >= 65 && c <= 90)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
