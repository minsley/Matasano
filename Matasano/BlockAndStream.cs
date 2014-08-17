using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Matasano
{
    public static class BlockAndStream
    {
        public static byte[] Pad(byte[] input, int length)
        {
            var padLength = length - input.Length;
            var output = new byte[length];

            Array.Copy(input, output, input.Length);
            for (var i = 0; i < padLength; i++)
            {
                output[input.Length + i] = (byte) padLength;
            }

            return output;
        }
    }
}
