using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Text;
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

        // Single-byte xor
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

                var plainBytes = Basic.XorRepeatKey(cipherTextBytes, keyBytes);

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

        // Detect single-character xor
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
                    var translation = Basic.XorRepeatKey(Basic.HexToByteArray(cipher), new[] {key});
                    if(Basic.IsEnglish(translation, Basic.EnglishCharacterFrequencies) > 0.5)
                        Console.WriteLine("key: {0}[{1}] - trans: {2}",
                            Basic.BytesToHex(new[] { key }),
                            Basic.BytesToAscii(new[] { key }),
                            Basic.BytesToAscii(translation));
                }
            }
        }

        // Implement repeating-key xor
        [TestMethod]
        public void TestS1C5()
        {
            const string message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            const string target = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            const string key = "ICE";

            var messageBytes = Basic.AsciiToBytes(message);
            var keyBytes = Basic.AsciiToBytes(key);
            var eMessageBytes = Basic.XorRepeatKey(messageBytes, keyBytes);
            var eMessage = Basic.BytesToHex(eMessageBytes);
            Assert.AreEqual(target, eMessage);
        }

        // Break repeating-key Xor (Vignere Cipher)
        [TestMethod]
        public void TestS1C6()
        {
            const int maxKeysize = 40;
            const string filePath = @"..\..\Assets\S1C6.txt";

            string cipherText;

            using (var s = new StreamReader(filePath))
            {
                var sb = new StringBuilder();
                while (!s.EndOfStream)
                {
                    sb.Append(s.ReadLine());
                }
                cipherText = sb.ToString();
            }

            var keysize = Basic.GetKeysize(Basic.AsciiToBytes(cipherText.Substring(0,maxKeysize*2)), maxKeysize);


            var cipherBytes = Basic.AsciiToBytes(cipherText);

            var cipherBlocks = new List<byte[]>();
            for(var i=0; i<keysize; i++) cipherBlocks.Add(new byte[cipherText.Length/keysize]);

            for (var i = 0; i < cipherText.Length; i++)
            {
                if(i + keysize > cipherText.Length) break;
                cipherBlocks[i%keysize][i/keysize] = cipherBytes[i];
            }

            var keys = new List<byte>();
            foreach (var block in cipherBlocks)
            {
                List<Tuple<double, byte, char>> matches;
                Basic.IsLanguage(block, Basic.EnglishCharacterFrequencies, out matches);
                keys.Add(Basic.GetKeysFromLanguageMatches(matches, 1)[0]); 
            }

            var messageBytes = Basic.XorRepeatKey(cipherBytes, keys.ToArray());
            Console.WriteLine(Basic.BytesToAscii(messageBytes));
        }
    }
}
