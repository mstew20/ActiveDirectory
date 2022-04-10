using System;
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

        public static T GetValue<T>(this ResultPropertyValueCollection result, Func<object, T> converter = null)
        {
            T output;
            if (result.Count > 0)
            {
                var value = result[0];
                if (converter is not null)
                {
                    output = converter.Invoke(value);
                }
                else
                {
                    output = (T)Convert.ChangeType(value, typeof(T));
                }

                return output;
            }

            return default;
        }
    }
}
