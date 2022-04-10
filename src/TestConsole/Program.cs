using System.DirectoryServices;

var t = GetValue<bool>(0);
Console.WriteLine(t);


static T GetValue<T>(object result, Func<object, T> converter = null)
{
    T output;
    if (result is not null)
    {
        if (converter is not null)
        {
            output = converter.Invoke(result);
        }
        else
        {
            output = (T)Convert.ChangeType(result, typeof(T));
        }

        return output;
    }

    return default(T);
}