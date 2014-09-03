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
            var start = new byte[] 
            {
                0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
            };

            var end = start;

            for (var i = 0; i < end.Length; i++)
            {
                Console.Write(end[i] + " ");
            }
            Console.WriteLine();

            Basic.Aes.Util.ShiftRows(ref end, false);

            for (var i = 0; i < end.Length; i++)
            {
                Console.Write(end[i] + " ");
            }
            Console.WriteLine();

            Basic.Aes.Util.ShiftRows(ref end, true);

            for (var i = 0; i < end.Length; i++)
            {
                Console.Write(end[i] + " ");
            }
        }

        [TestMethod]
        public void TestMixColumns()
        {
            var control1 = new byte[]
            {
                0,1,2,3,4,5,6,7,8,9,19,11,12,13,14,15
            };

            var result1 = control1;

            PrintByteArray(result1);

            Basic.Aes.Util.MixColumns(ref result1);

            PrintByteArray(result1);

            Basic.Aes.Util.MixColumns(ref result1, true);

            PrintByteArray(result1);

            CollectionAssert.AreEqual(control1, result1, "Failed: operation is not reversable.");
            Console.WriteLine();

            var control2 = new byte[]
            {
                66, 80, 228, 230, 148, 33, 121, 29, 106, 95, 226, 146, 255, 98, 121, 117
            };

            var result2 = new byte[]
            {
                56, 148, 235, 60, 169, 208, 98, 95, 150, 3, 225, 112, 68, 11, 110, 15
            };

            PrintByteArray(result2);

            Basic.Aes.Util.MixColumns(ref result2);

            PrintByteArray(result2);

            CollectionAssert.AreEqual(control2, result2, "Failed: Mixcolumn did not produce expected result.");
        }

        [TestMethod]
        public void TestExpandKey()
        {
            var e128 = Basic.Aes.Util.ExpandKey(new byte[16], 10);
            var e128Answer = new List<string> { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "9b", "98", "98", "c9", "f9", "fb", "fb", "aa", "9b", "98", "98", "c9", "f9", "fb", "fb", "aa", "90", "97", "34", "50", "69", "6c", "cf", "fa", "f2", "f4", "57", "33", "0b", "0f", "ac", "99", "ee", "06", "da", "7b", "87", "6a", "15", "81", "75", "9e", "42", "b2", "7e", "91", "ee", "2b", "7f", "2e", "2b", "88", "f8", "44", "3e", "09", "8d", "da", "7c", "bb", "f3", "4b", "92", "90", "ec", "61", "4b", "85", "14", "25", "75", "8c", "99", "ff", "09", "37", "6a", "b4", "9b", "a7", "21", "75", "17", "87", "35", "50", "62", "0b", "ac", "af", "6b", "3c", "c6", "1b", "f0", "9b", "0e", "f9", "03", "33", "3b", "a9", "61", "38", "97", "06", "0a", "04", "51", "1d", "fa", "9f", "b1", "d4", "d8", "e2", "8a", "7d", "b9", "da", "1d", "7b", "b3", "de", "4c", "66", "49", "41", "b4", "ef", "5b", "cb", "3e", "92", "e2", "11", "23", "e9", "51", "cf", "6f", "8f", "18", "8e" };

            for (var i=0; i<e128.Length; i++)
            {
                if(i%16 == 0) Console.WriteLine();
                var byteString = e128[i].ToString("x2");
                Assert.AreEqual(e128Answer[i], byteString);
                Console.Write(byteString + " ");
            }
            Console.WriteLine();

            var e192 = Basic.Aes.Util.ExpandKey(new byte[24], 12);
            var e192Answer = new List<string> { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "9b", "98", "98", "c9", "f9", "fb", "fb", "aa", "9b", "98", "98", "c9", "f9", "fb", "fb", "aa", "9b", "98", "98", "c9", "f9", "fb", "fb", "aa", "90", "97", "34", "50", "69", "6c", "cf", "fa", "f2", "f4", "57", "33", "0b", "0f", "ac", "99", "90", "97", "34", "50", "69", "6c", "cf", "fa", "c8", "1d", "19", "a9", "a1", "71", "d6", "53", "53", "85", "81", "60", "58", "8a", "2d", "f9", "c8", "1d", "19", "a9", "a1", "71", "d6", "53", "7b", "eb", "f4", "9b", "da", "9a", "22", "c8", "89", "1f", "a3", "a8", "d1", "95", "8e", "51", "19", "88", "97", "f8", "b8", "f9", "41", "ab", "c2", "68", "96", "f7", "18", "f2", "b4", "3f", "91", "ed", "17", "97", "40", "78", "99", "c6", "59", "f0", "0e", "3e", "e1", "09", "4f", "95", "83", "ec", "bc", "0f", "9b", "1e", "08", "30", "0a", "f3", "1f", "a7", "4a", "8b", "86", "61", "13", "7b", "88", "5f", "f2", "72", "c7", "ca", "43", "2a", "c8", "86", "d8", "34", "c0", "b6", "d2", "c7", "df", "11", "98", "4c", "59", "70" };

            for (var i = 0; i < e192.Length; i++)
            {
                if (i % 16 == 0) Console.WriteLine();
                var byteString = e192[i].ToString("x2");
                Assert.AreEqual(e192Answer[i], byteString);
                Console.Write(byteString + " ");
            }
            Console.WriteLine();

            var e256 = Basic.Aes.Util.ExpandKey(new byte[32], 14);
            var e256Answer = new List<string> { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "62", "63", "63", "63", "aa", "fb", "fb", "fb", "aa", "fb", "fb", "fb", "aa", "fb", "fb", "fb", "aa", "fb", "fb", "fb", "6f", "6c", "6c", "cf", "0d", "0f", "0f", "ac", "6f", "6c", "6c", "cf", "0d", "0f", "0f", "ac", "7d", "8d", "8d", "6a", "d7", "76", "76", "91", "7d", "8d", "8d", "6a", "d7", "76", "76", "91", "53", "54", "ed", "c1", "5e", "5b", "e2", "6d", "31", "37", "8e", "a2", "3c", "38", "81", "0e", "96", "8a", "81", "c1", "41", "fc", "f7", "50", "3c", "71", "7a", "3a", "eb", "07", "0c", "ab", "9e", "aa", "8f", "28", "c0", "f1", "6d", "45", "f1", "c6", "e3", "e7", "cd", "fe", "62", "e9", "2b", "31", "2b", "df", "6a", "cd", "dc", "8f", "56", "bc", "a6", "b5", "bd", "bb", "aa", "1e", "64", "06", "fd", "52", "a4", "f7", "90", "17", "55", "31", "73", "f0", "98", "cf", "11", "19", "6d", "bb", "a9", "0b", "07", "76", "75", "84", "51", "ca", "d3", "31", "ec", "71", "79", "2f", "e7", "b0", "e8", "9c", "43", "47", "78", "8b", "16", "76", "0b", "7b", "8e", "b9", "1a", "62", "74", "ed", "0b", "a1", "73", "9b", "7e", "25", "22", "51", "ad", "14", "ce", "20", "d4", "3b", "10", "f8", "0a", "17", "53", "bf", "72", "9c", "45", "c9", "79", "e7", "cb", "70", "63", "85" };

            for (var i = 0; i < e256.Length; i++)
            {
                if (i % 16 == 0) Console.WriteLine();
                var byteString = e256[i].ToString("x2");
                Assert.AreEqual(e256Answer[i], byteString);
                Console.Write(byteString + " ");
            }
            Console.WriteLine();
        }

        [TestMethod]
        public void TestAesBlock()
        {
            // http://seit.unsw.adfa.edu.au/staff/sites/lpb/src/AEScalc/

            var key = Basic.HexToBytes("000102030405060708090a0b0c0d0e0f");
            var text = Basic.HexToBytes("00112233445566778899aabbccddeeff");
            var cipherText = Basic.HexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a");

            var cipher = Basic.Aes.RunAes(text, key);

            var decipher = Basic.Aes.RunAes(cipher, key, true);

            Console.WriteLine(Basic.BytesToAscii(decipher));

            CollectionAssert.AreEqual(cipher, cipherText);
            CollectionAssert.AreEqual(decipher, text);
        }

        private void PrintByteArray(byte[] array)
        {
            foreach (var o in array)
            {
                Console.Write(o.ToString("x") + " ");
            }
            Console.WriteLine();
        }
    }
}
