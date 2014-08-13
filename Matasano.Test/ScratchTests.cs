using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Matasano.Test
{
    /// <summary>
    /// Summary description for ScratchTests
    /// </summary>
    [TestClass]
    public class ScratchTests
    {
        [TestMethod]
        public void ParseCharacterCountsFile()
        {
            const string path = @"..\..\Assets\CharacterCounts-Fiction.txt";

            var counts = new Dictionary<char, int>();
            var weights = new Dictionary<char, double>();

            using (var s = new StreamReader(path))
            {
                var lineNumber = 0;
                while (!s.EndOfStream)
                {
                    var line = s.ReadLine();
                    lineNumber++;

                    if (lineNumber < 3 || line == null) continue;
                    if ("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".Contains(line[0]))
                        counts.Add(line[0], int.Parse(line.Substring(2)));
                }
            }

            var total = counts.Sum(x => x.Value);
            foreach (var count in counts)
            {
                weights.Add(count.Key, (double)count.Value / total);
            }

            foreach (var weight in weights)
            {
                Console.WriteLine("{0} {1:F12}", weight.Key, weight.Value);
            }
        }
    }
}
