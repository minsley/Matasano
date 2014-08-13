using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Matasano
{
    public static class Basic
    {

        public static byte[] AsciiToByteArray(string ascii)
        {
            return Encoding.ASCII.GetBytes(ascii);
        }

        public static string ByteArrayToAscii(byte[] byteArray)
        {
            return Encoding.ASCII.GetString(byteArray);
        }

        public static string ByteArrayToHex(byte[] byteArray)
        {
            return BitConverter.ToString(byteArray).Replace("-", "");
        }

        public static string ByteArrayToBase64(byte[] byteArray)
        {
            return Convert.ToBase64String(byteArray);
        }

        public static byte[] HexToByteArray(string hexInput)
        {
            if (hexInput.Length%2 != 0) hexInput = "0" + hexInput;
            var byteArray = new byte[hexInput.Length/2];
            for (var i = 0; i < hexInput.Length/2; i++)
            {
                byteArray[i] = Convert.ToByte(hexInput.Substring(i*2, 2), 16);
            }
            return byteArray;
        }

        public static string HexToBase64(string hexInput)
        {
            return ByteArrayToBase64(HexToByteArray(hexInput));
        }

        public static byte[] Xor(byte[] buf1, byte[] buf2)
        {
            if (buf1.Length != buf2.Length) throw new Exception("Inputs must be equal length.");
            var xor = new byte[buf1.Length];
            for (var i = 0; i < buf1.Length; i++)
            {
                xor[i] = Convert.ToByte(buf1[i] ^ buf2[i]);
            }
            return xor;
        }

        public static byte[] Decipher(byte[] cipher, byte[] key)
        {
            var keyRepeat = new byte[cipher.Length];
            for (var i = 0; i < cipher.Length; i++) keyRepeat[i] = key[i % key.Length];
            return Xor(cipher, keyRepeat);
        }

        /// <summary>
        /// Uses character frequency to estimate the probability that the text provided is written in English.
        /// </summary>
        /// <param name="plainText">A string of text.</param>
        /// <returns>0 to 1 probability of input text being English.</returns>
        public static double IsEnglish(string plainText)
        {
            var plainTextContents = new Dictionary<char, int>();

            // source: http://en.wikipedia.org/wiki/Letter_frequency
            var englishCharacterFrequencies = new Dictionary<char, double>
            {
                {'a',0.08167}, {'b',0.01492}, {'c',0.02782}, {'d',0.04253}, {'e',0.13000},
                {'f',0.02228}, {'g',0.02015}, {'h',0.06094}, {'i',0.06966}, {'j',0.00153},
                {'k',0.00772}, {'l',0.04025}, {'m',0.02406}, {'n',0.06749}, {'o',0.07507},
                {'p',0.01929}, {'q',0.00095}, {'r',0.05987}, {'s',0.06327}, {'t',0.09056},
                {'u',0.02758}, {'v',0.00978}, {'w',0.02360}, {'x',0.00150}, {'y',0.01974},
                {'z',0.00074},
            };

            foreach (var character in plainText.ToLower())
            {
                if (plainTextContents.ContainsKey(character))
                    plainTextContents[character] += 1;
                else
                    plainTextContents.Add(character, 1);
            }

            var score = 0d;
            foreach (var character in plainTextContents)
            {
                if (englishCharacterFrequencies.ContainsKey(character.Key))
                {
                    var weight = character.Value / (double)plainText.Length;
                    var ideal = englishCharacterFrequencies[character.Key];
                    score += ideal * (1 - Math.Abs(weight - ideal));
                }
            }

            return score;
        }

        /// <summary>
        /// Estimates how close a given string (as byte array) is to being English distributed.
        /// </summary>
        /// <param name="bytes">String represented as byte array</param>
        /// <param name="matches">List of tuples of (weight difference, byte-word, character)</param>
        /// <returns>0 to 1 distribution.</returns>
        public static double IsEnglishDistributed(byte[] bytes, out List<Tuple<double, byte, char>> matches)
        {
            var byteWords = new Dictionary<byte, int>();

            // source: http://en.wikipedia.org/wiki/Letter_frequency
            var englishCharacters = new Dictionary<char, double>
            {
                {'a',0.08167}, {'b',0.01492}, {'c',0.02782}, {'d',0.04253}, {'e',0.13000},
                {'f',0.02228}, {'g',0.02015}, {'h',0.06094}, {'i',0.06966}, {'j',0.00153},
                {'k',0.00772}, {'l',0.04025}, {'m',0.02406}, {'n',0.06749}, {'o',0.07507},
                {'p',0.01929}, {'q',0.00095}, {'r',0.05987}, {'s',0.06327}, {'t',0.09056},
                {'u',0.02758}, {'v',0.00978}, {'w',0.02360}, {'x',0.00150}, {'y',0.01974},
                {'z',0.00074},
            };

            // Build list of byte-words and their counts
            foreach (var b in bytes)
            {
                if (byteWords.ContainsKey(b))
                    byteWords[b] += 1;
                else
                    byteWords.Add(b, 1);
            }

            // Build ordered list of weight differences
            var stack = (
                from b in byteWords 
                from c in englishCharacters 
                select 
                    new Tuple<double, byte, char>(
                        Math.Abs((double) b.Value/bytes.Length - c.Value), 
                        b.Key, 
                        c.Key)).ToList();
            stack.Sort((first, next) => first.Item1.CompareTo(next.Item1));

            // Take the best matches, one for each english character
            matches = new List<Tuple<double, byte, char>>();
            while (stack.Count > 0)
            {
                var top = stack[0]; stack.RemoveAt(0);
                if(matches.All(x => x.Item3 != top.Item3 && x.Item2 != top.Item2))
                    matches.Add(top);
            }

            // Finally, score the englishiness of the input
            var score = 0d;
            foreach (var match in matches)
            {
                var ideal = englishCharacters[match.Item3];
                score += (ideal * (1 - match.Item1));
            }
            return score;
        }
    }
}
