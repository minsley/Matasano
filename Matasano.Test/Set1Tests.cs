using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Matasano.Test
{
    [TestClass]
    public class Set1Tests
    {
        // Convert Hex to Base64
        [TestMethod]
        public void TestS1C1()
        {
            // Hex -> Ascii "I'm killing your brain like a poisonous mushroom" :D
            const string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            const string target = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            Assert.AreEqual(target, Basic.HexToBase64(input));
        }

        // Xor the input and fixed val to get the target
        [TestMethod]
        public void TestS1C2()
        {
            const string input = "1c0111001f010100061a024b53535009181c";
            const string fixedXor = "686974207468652062756c6c277320657965";
            const string target = "746865206b696420646f6e277420706c6179";

            var inputByteArray = Basic.HexToByteArray(input);
            var fixedXorByteArray = Basic.HexToByteArray(fixedXor);

            var xor = Basic.Xor(inputByteArray, fixedXorByteArray);
            Assert.AreEqual(Basic.BytesToHex(xor).ToUpper(), target.ToUpper());
        }

        [TestMethod]
        public void TestS1C3()
        {
            const string cipherText = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

            var tests = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            var results = new List<Tuple<double, char, string>>();

            for (var i = 0; i < tests.Length; i++)
            {
                var key = ((int) tests[i]).ToString("X");
                var keyBytes = Basic.HexToByteArray(key);
                var cipherTextBytes = Basic.HexToByteArray(cipherText);

                var plainBytes = Basic.Decipher(cipherTextBytes, keyBytes);

                var score = Basic.IsEnglish(plainBytes, Basic.EnglishCharacterFrequencies);
                var plainText = Basic.BytesToAscii(plainBytes);

                results.Add(new Tuple<double, char, string>(score, tests[i], plainText));
            }

            results.Sort((firstPair, nextPair) => nextPair.Item1.CompareTo(firstPair.Item1));
            foreach (var result in results)
            {
                Console.WriteLine("{0:P1} - key: {1} - message: {2}", result.Item1, result.Item2, result.Item3.Replace("\n","\\n"));
            }
        }

        [TestMethod]
        public void TestS1C4()
        {
            const string path = @"..\..\Assets\S1C4.txt";

            var ciphers = new List<string>();
            var cipherMatches = new List<List<Tuple<double, byte, char>>>();

            using (var r = new StreamReader(path))
            {
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    List<Tuple<double, byte, char>> matches;
                    var score = Basic.IsLanguage(Basic.HexToByteArray(line), Basic.EnglishCharacterFrequencies, out matches);
                    
                    if (score <= 0.8) continue;
                    ciphers.Add(line);
                    cipherMatches.Add(matches);
                }
            }

            for (var i=0; i<ciphers.Count; i++)
            {
                var cipher = ciphers[i];
                var cipherMatch = cipherMatches[i];

                Console.WriteLine("\n-- Cipher: {0} --", cipher);

                var keys = Basic.GetKeysFromLanguageMatches(cipherMatch, 5);
                foreach (var key in keys)
                {
                    var translation = Basic.Decipher(Basic.HexToByteArray(cipher), new[] {key});
                    if(Basic.IsEnglish(translation, Basic.EnglishCharacterFrequencies) > 0.5)
                        Console.WriteLine("key: {0}[{1}] - trans: {2}",
                            Basic.BytesToHex(new[] { key }),
                            Basic.BytesToAscii(new[] { key }),
                            Basic.BytesToAscii(translation));
                }
            }
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
            matches.Sort((first, next) => next.Item1.CompareTo(first.Item1));

            var keys = new Dictionary<byte, double>();

            Console.WriteLine("-- {0:P} similar to English character distribution --", score);
            foreach (var match in matches)
            {
                var key = Basic.Xor(Basic.AsciiToBytes(match.Item3 + ""),new []{match.Item2});
                if (keys.ContainsKey(key[0]))
                    keys[key[0]] += match.Item1;
                else
                    keys.Add(key[0], match.Item1);

                Console.WriteLine("Score: {0:P} - Char: {1} - Byte: {2} - Key: {3}", 
                    match.Item1, match.Item3, 
                    Basic.BytesToAscii(new []{match.Item2}),
                    Basic.BytesToHex(key));
            }

            Console.WriteLine("\n-- Possible Keys --");
            foreach (var key in keys.OrderByDescending(x => x.Value))
            {
                Console.WriteLine("score: {0:P} - key: {1}", key.Value, Basic.BytesToHex(new [] {key.Key}));
            }
        }
    }
}
