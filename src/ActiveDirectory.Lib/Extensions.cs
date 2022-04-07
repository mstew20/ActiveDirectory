using System.DirectoryServices;

#pragma warning disable CA1416
namespace ActiveDirectory.Lib
{
    public static class Extensions
    {
        public static object Value(this ResultPropertyValueCollection result)
        {
            if (result.Count > 0)
            {
                return result[0];
            }

            return null;
        }
    }
}
