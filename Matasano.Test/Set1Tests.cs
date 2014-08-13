using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            Assert.AreEqual(Basic.ByteArrayToHex(xor).ToUpper(), target.ToUpper());
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

                var plainText = Basic.ByteArrayToAscii(plainBytes);
                var score = Basic.IsEnglish(plainText);

                results.Add(new Tuple<double, char, string>(score, tests[i], plainText));
            }

            results.Sort((firstPair, nextPair) => nextPair.Item1.CompareTo(firstPair.Item1));
            foreach (var result in results)
            {
                Console.WriteLine("{0:P1}% - key: {1} - string: {2}", result.Item1, result.Item2, result.Item3.Replace("\n","\\n"));
            }
        }

        [TestMethod]
        public void TestS1C4()
        {
            const string path = @"..\..\Assets\S1C4.txt";

            string cipher;

            using (var r = new StreamReader(path))
            {
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    List<Tuple<double,byte,char>> matches;
                    var score = Basic.IsEnglishDistributed(Basic.HexToByteArray(line), out matches);
                    
                    Console.WriteLine("{0:P} - {1}", score, line);
                }
            }
        }

        [TestMethod]
        public void TestIsEnglishDistributed()
        {
            const string cipherText = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

            var bytes = Basic.HexToByteArray(cipherText);
            var matches = new List<Tuple<double, byte, char>>();

            var score = Basic.IsEnglishDistributed(bytes, out matches);

            Console.WriteLine("-- Score: {0:P} English --", score);
            foreach (var match in matches)
            {
                Console.WriteLine("Score: {0:P} - Char: {1} - Byte: {2} - Xor: {3}", 
                    match.Item1, match.Item3, 
                    Basic.ByteArrayToAscii(new []{match.Item2}),
                    Basic.ByteArrayToHex(Basic.Xor(Basic.AsciiToByteArray(match.Item3 + ""),new []{match.Item2})));
            }

            var first = matches.First();
            var key = Basic.Xor(new[] { first.Item2 }, Basic.AsciiToByteArray("X"));//first.Item3 + ""));
            var keyChar = Basic.ByteArrayToAscii(key);

            Console.WriteLine("\n-- Key: {0}[{1}] --", Basic.ByteArrayToHex(key), keyChar);
            Console.WriteLine("Original: " + cipherText);
            var transbytes = Basic.Decipher(Basic.HexToByteArray(cipherText), key);
            Console.WriteLine("Deciphered: " + Basic.ByteArrayToHex(transbytes));
            Console.WriteLine("Plaintext: " + Basic.ByteArrayToAscii(transbytes));
        }
    }
}
