using System.DirectoryServices;

namespace EzActiveDirectory
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
