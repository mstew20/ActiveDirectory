using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EzActiveDirectory.Models;
public record Bitlocker(string Key, byte[] KeyIDBytes)
{
    public string KeyID => ConvertID(KeyIDBytes);
    public string ComputerName { get; set; }
    public DateTime Date { get; set; }

    private string ConvertID(byte[] id)
	{
		StringBuilder sb = new();
        sb.Append(id[3].ToString("X02"));
        sb.Append(id[2].ToString("X02"));
        sb.Append(id[1].ToString("X02"));
        sb.Append(id[0].ToString("X02"));
        sb.Append('-');
		sb.Append(id[5].ToString("X02"));
		sb.Append(id[4].ToString("X02"));
		sb.Append('-');
		sb.Append(id[7].ToString("X02"));
		sb.Append(id[6].ToString("X02"));
		sb.Append('-');
		sb.Append(id[8].ToString("X02"));
		sb.Append(id[9].ToString("X02"));
		sb.Append('-');
		sb.Append(id[10].ToString("X02"));
		sb.Append(id[11].ToString("X02"));
		sb.Append(id[12].ToString("X02"));
		sb.Append(id[13].ToString("X02"));
		sb.Append(id[14].ToString("X02"));
		sb.Append(id[15].ToString("X02"));
		
		return sb.ToString();
	}
}
