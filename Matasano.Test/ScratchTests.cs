using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
        public void TestGetHammingDistance()
        {
            const string input1 = "this is a test";
            const string input2 = "wokka wokka!!!";
            const int hammingDistance = 37;

            var input1Bytes = Basic.AsciiToBytes(input1);
            var input2Bytes = Basic.AsciiToBytes(input2);

            var result = Basic.GetHammingDistance(input1Bytes, input2Bytes);

            Assert.AreEqual(hammingDistance, result);
        }

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

        [TestMethod]
        public void TestGetRepeatKeySplit()
        {
            const string message = "0000011111";

            Console.WriteLine("Message: {0}\n", message);

            var messageB = Basic.AsciiToBytes(message);
            var split2 = Basic.GetRepeatKeySplit(messageB, 2);
            var split5 = Basic.GetRepeatKeySplit(messageB, 5);

            Console.WriteLine("Split on 2key:\n");
            foreach (var split in split2)
            {
                    Console.WriteLine(Basic.BytesToAscii(split));
            }

            Console.WriteLine("\nSplit on 5key:\n");
            foreach (var split in split5)
            {
                Console.WriteLine(Basic.BytesToAscii(split));
            }
        }

        [TestMethod]
        public void EncipherText()
        {
            var message = Basic.AsciiToBytes(Basic.GetFileText(@"..\..\Assets\TestIsEnglishDistributed.txt"));
            var key = Basic.AsciiToBytes("ICE");
            var cipher = Basic.XorRepeatKey(message, key);
            Console.WriteLine(Basic.BytesToHex(cipher));
        }

        [TestMethod]
        public void TestBlockify()
        {
            var message = "YELLOW SUBMARINE";
            Console.WriteLine("input: {0}", message);

            var input = Basic.AsciiToBytes(message);

            var blocked = Basic.Aes.Util.Blockify(input, 4, input.Length/4);

            for (var i = 0; i < blocked.GetLength(0); i++)
            {
                for (var j = 0; j < blocked.GetLength(1); j++)
                {
                    Console.Write((char)blocked[i,j] + " ");
                }
                Console.Write('\n');
            }

            var unblocked = Basic.Aes.Util.Unblockify(blocked);

            var output = Basic.BytesToAscii(unblocked);
            Console.WriteLine("output: {0}", output);

            Assert.AreEqual(message, output);
        }

        [TestMethod]
        public void TestShiftRows()
        {
            var start = new byte[4,4]
            {
                {0,1,2,3},
                {0,1,2,3},
                {0,1,2,3},
                {0,1,2,3}
            };

            var end = new byte[4, 4];
            Array.Copy(start, end, 16);

            for (var i = 0; i < end.GetLength(0); i++)
            {
                for (var j = 0; j < end.GetLength(1); j++)
                {
                    Console.Write(end[i, j] + " ");
                }
                Console.Write('\n');
            }
            Console.WriteLine();

            Basic.Aes.Util.ShiftRows(ref end, true);

            for (var i = 0; i < end.GetLength(0); i++)
            {
                for (var j = 0; j < end.GetLength(1); j++)
                {
                    Console.Write(end[i, j] + " ");
                }
                Console.Write('\n');
            }
            Console.WriteLine();

            Basic.Aes.Util.ShiftRows(ref end, false);

            for (var i = 0; i < start.GetLength(0); i++)
            {
                for (var j = 0; j < end.GetLength(1); j++)
                {
                    Console.Write(end[i, j] + " ");
                }
                Console.Write('\n');
            }
        }
    }
}
