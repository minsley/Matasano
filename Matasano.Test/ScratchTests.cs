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
        public void TestIsLanguage()
        {
            const string path = @"..\..\Assets\TestIsEnglishDistributed.txt";

            string plaintext;
            using (var s = new StreamReader(path))
            {
                plaintext = s.ReadToEnd().ToLower();
            }

            var bytes = Basic.AsciiToBytes(plaintext);
            List<Tuple<double, byte, char>> matches;

            var score = Basic.IsLanguage(bytes, Basic.EnglishCharacterFrequencies, out matches);
            matches.Sort((first, next) => next.Item1.CompareTo(first.Item1));

            var keys = new Dictionary<byte, double>();

            Console.WriteLine("-- {0:P} similar to English character distribution --", score);
            foreach (var match in matches)
            {
                var key = Basic.Xor(Basic.AsciiToBytes(match.Item3 + ""), new[] { match.Item2 });
                if (keys.ContainsKey(key[0]))
                    keys[key[0]] += match.Item1;
                else
                    keys.Add(key[0], match.Item1);

                Console.WriteLine("Score: {0:P} - Char: {1} - Byte: {2} - Key: {3}",
                    match.Item1, match.Item3,
                    Basic.BytesToAscii(new[] { match.Item2 }),
                    Basic.BytesToHex(key));
            }

            Console.WriteLine("\n-- Possible Keys --");
            foreach (var key in keys.OrderByDescending(x => x.Value))
            {
                Console.WriteLine("score: {0:P} - key: {1}", key.Value, Basic.BytesToHex(new[] { key.Key }));
            }
        }

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
