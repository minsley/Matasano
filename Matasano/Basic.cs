using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Text.RegularExpressions;

namespace Matasano
{
    public static class Basic
    {
        public static Dictionary<char, double> EnglishLetterFrequencies {
            get
            {
                // source: http://en.wikipedia.org/wiki/Letter_frequency
                return new Dictionary<char, double>
                {
                    {'a',0.08167}, {'b',0.01492}, {'c',0.02782}, {'d',0.04253}, {'e',0.13000},
                    {'f',0.02228}, {'g',0.02015}, {'h',0.06094}, {'i',0.06966}, {'j',0.00153},
                    {'k',0.00772}, {'l',0.04025}, {'m',0.02406}, {'n',0.06749}, {'o',0.07507},
                    {'p',0.01929}, {'q',0.00095}, {'r',0.05987}, {'s',0.06327}, {'t',0.09056},
                    {'u',0.02758}, {'v',0.00978}, {'w',0.02360}, {'x',0.00150}, {'y',0.01974},
                    {'z',0.00074},
                };
            }
        }

        public static Dictionary<char, double> EnglishCharacterFrequencies
        {
            get
            {
                // source: http://millikeys.sourceforge.net/freqanalysis.html
                return new Dictionary<char, double>()
                {
                    {' ', 0.187559814195}, {'e', 0.096064558135}, {'t', 0.070228741129}, {'a', 0.062089098108}, {'o', 0.058436260858}, 
                    {'i', 0.052205454975}, {'n', 0.052090056092}, {'h', 0.048683276415}, {'s', 0.047751779968}, {'r', 0.044349942550}, 
                    {'d', 0.035214859696}, {'l', 0.032025541986}, {'u', 0.022513177595}, {'m', 0.019438050430}, {'c', 0.018796166182}, 
                    {'w', 0.018208358954}, {'g', 0.016586113169}, {'f', 0.016238604461}, {'y', 0.015572252662}, {'p', 0.013135846285}, 
                    {',', 0.012407140609}, {'.', 0.012136078735}, {'b', 0.011912624345}, {'k', 0.007398625780}, {'v', 0.007118620647}, 
                    {'"', 0.006654613624}, {'\'', 0.004406215323}, {'-', 0.002593184358}, {'?', 0.001218422297}, {'x', 0.001178705312}, 
                    {'j', 0.001162693536}, {';', 0.000807421385}, {'!', 0.000779404017}, {'Q', 0.000713427718}, {'z', 0.000696923272}, 
                    {':', 0.000250877961}, {'1', 0.000163742780}, {'0', 0.000103992275}, {')', 0.000100424307}, {'*', 0.000099765685}, 
                    {'(', 0.000099104470}, {'2', 0.000095891742}, {'`', 0.000094011817}, {'3', 0.000066873477}, {'9', 0.000064786111}, 
                    {'5', 0.000056695951}, {'4', 0.000054922338}, {'8', 0.000048885834}, {'7', 0.000044402536}, {'6', 0.000044099155}, 
                    {'/', 0.000043450905}, {'_', 0.000030091768}, {'[', 0.000029995827}, {']', 0.000029910258}, {'=', 0.000025668110}, 
                    {'>', 0.000011686652}, {'~', 0.000010545732}, {'<', 0.000010359036}, {'#', 0.000008219811}, {'&', 0.000006975171}, 
                    {'{', 0.000005854995}, {'}', 0.000005554207}, {'^', 0.000004439216}, {'|', 0.000003920616}, {'\\', 0.000003542038}, 
                    {'@', 0.000003510922}, {'%', 0.000003020845}, {'$', 0.000002722650}, 
                };
            }
        } 

        public static byte[] AsciiToBytes(string ascii)
        {
            return Encoding.ASCII.GetBytes(ascii);
        }

        public static string BytesToAscii(byte[] bytes)
        {
            return Encoding.ASCII.GetString(bytes);
        }

        public static string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        public static byte[] HexToBytes(string hexInput)
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
            return BytesToBase64(HexToBytes(hexInput));
        }

        public static byte[] Base64ToBytes(string cipherText)
        {
            return Convert.FromBase64String(cipherText);
        }

        public static string BytesToBase64(byte[] byteArray)
        {
            return Convert.ToBase64String(byteArray);
        }

        public static string GetFileText(string path)
        {
            using (var s = new StreamReader(path))
            {
                var sb = new StringBuilder();
                while (!s.EndOfStream)
                {
                    sb.Append(s.ReadLine());
                }
                return sb.ToString();
            }
        }

        public static byte[] Xor(byte[] buf1, byte[] buf2)
        {
            if (buf1.Length != buf2.Length) throw new Exception("Xor inputs must be equal length.");
            var xor = new byte[buf1.Length];
            for (var i = 0; i < buf1.Length; i++)
            {
                xor[i] = Convert.ToByte(buf1[i] ^ buf2[i]);
            }
            return xor;
        }

        public static byte[] XorRepeatKey(byte[] input, byte[] key)
        {
            var keyRepeat = new byte[input.Length];
            for (var i = 0; i < input.Length; i++) keyRepeat[i] = key[i % key.Length];
            return Xor(input, keyRepeat);
        }

        public static int GetHammingDistance(byte[] input1, byte[] input2)
        {
            if (input1.Length != input2.Length) throw new Exception("Inputs must be equal length.");

            var result = 0;
            for (var i = 0; i < input1.Length; i++)
            {
                var xor = input1[i] ^ input2[i];
                for (var j = 0; j <= 7; j++)
                {
                    result += (xor >> j) & 1;
                }
            }
            return result;
        }

        public static List<Tuple<byte, double>> GetByteFrequencies(byte[] bytes)
        {
            var results = new List<Tuple<byte, double>>();
            var contents = new Dictionary<byte, int>();

            foreach (var b in bytes)
            {
                if (contents.ContainsKey(b))
                    contents[b] ++;
                else
                    contents.Add(b, 1);
            }

            var n = bytes.Length;
            foreach (var c in contents)
            {
                var weight = c.Value / (double)n;
                results.Add(new Tuple<byte, double>(c.Key, weight));
            }

            return results;
        }

        /// <summary>
        /// Uses character frequency to estimate the probability that the text provided is written in English.
        /// </summary>
        /// <param name="englishTextBytes">A bytearray of English text.</param>
        /// <param name="englishDictionary">The dictionary to compare against.</param>
        /// <returns>0 to 1 probability of input text being English.</returns>
        public static double IsEnglish(byte[] englishTextBytes, Dictionary<char, double> englishDictionary)
        {
            var plainTextContents = new Dictionary<char, int>();

            var englishFrequencies = englishDictionary;

            var byteFrequencies = GetByteFrequencies(englishTextBytes);

            var score = 0d;
            foreach (var f in byteFrequencies)
            {
                if (englishFrequencies.ContainsKey((char)f.Item1))
                {
                    var idealWeight = englishFrequencies[(char)f.Item1];
                    score += idealWeight * (1 - Math.Abs(f.Item2 - idealWeight));
                }
            }

            return score;
        }

        /// <summary>
        /// Estimates how close a given string (as byte array) is to being English distributed.
        /// </summary>
        /// <param name="bytes">String represented as byte array</param>
        /// <param name="languageDictionary">The dictionary to compare against.</param>
        /// <param name="matches">List of tuples of (weight difference, byte-word, character)</param>
        /// <returns>0 to 1 distribution.</returns>
        public static double IsLanguage(byte[] bytes, Dictionary<char, double> languageDictionary, out List<Tuple<double, byte, char>> matches)
        {
            // Get byte frequency list
            var byteFrequencies = GetByteFrequencies(bytes);

            // Build ordered list of weight differences
            var stack = (
                from b in byteFrequencies
                from c in languageDictionary 
                select 
                    new Tuple<double, byte, char>(
                        Math.Abs(b.Item2 - c.Value), 
                        b.Item1, 
                        c.Key)).ToList();
            stack.Sort((first, next) => first.Item1.CompareTo(next.Item1));

            // Take the best matches, one for each english character
            matches = new List<Tuple<double, byte, char>>();
            while (stack.Count > 0)
            {
                var top = stack[0]; stack.RemoveAt(0);
                if (matches.Any(x => x.Item3 == top.Item3 || x.Item2 == top.Item2)) continue;
                var value = languageDictionary[top.Item3] * (1d - top.Item1);
                matches.Add(new Tuple<double, byte, char>(value, top.Item2, top.Item3));
            }

            matches.Sort((first, next) => next.Item1.CompareTo(first.Item1));

            return matches.Sum(match => match.Item1);
        }

        public static byte[] GetKeysFromLanguageMatches(List<Tuple<double, byte, char>> matches, int count)
        {
            var keys = new Dictionary<byte, double>();

            foreach (var match in matches)
            {
                var key = Xor(AsciiToBytes(match.Item3 + ""), new[] { match.Item2 });
                if (keys.ContainsKey(key[0]))
                    keys[key[0]] += match.Item1;
                else
                    keys.Add(key[0], match.Item1);
            }

            return keys.OrderByDescending(x => x.Value).ToList().GetRange(0,count).Select(x => x.Key).ToArray();
        }

        public static int GetKeysize(byte[] cipher, int maxKeysize, int n = 2)
        {
            if(n < 2) throw new Exception("N must be greater than or equal to 2 (default).");
            if(cipher.Length < n*maxKeysize) throw new Exception("Cipher length must be greater than mayKeysize * n.");

            var bestKeysize = 0;
            var leastNormalizedEditDistance = double.MaxValue;

            var keysizes = new int[maxKeysize];
            for (var i = 0; i < maxKeysize; i++) keysizes[i] = i+1;

            foreach (var keysize in keysizes)
            {
                var chunks = new List<byte[]>();
                for (var i = 0; i < n; i++)
                {
                    var temp = new byte[keysize];
                    Array.Copy(cipher,i*keysize,temp,0,keysize);
                    chunks.Add(temp);
                }

                var normalizedEditDistances = new List<double>();
                for (int i = 0; i < n; i++)
                {
                    for (int j = i+1; j < n; j++)
                    {
                        normalizedEditDistances.Add((double)GetHammingDistance(chunks[i], chunks[j])/keysize);
                    }
                }

                var meanNormalizedEditDistance = normalizedEditDistances.Average();
                if (meanNormalizedEditDistance < leastNormalizedEditDistance)
                {
                    leastNormalizedEditDistance = meanNormalizedEditDistance;
                    bestKeysize = keysize;
                }
            }

            return bestKeysize;
        }

        public static List<byte[]> GetRepeatKeySplit(byte[] cipher, int keylength)
        {
            var splits = new List<byte[]>();
            for (var i = 0; i < keylength; i++)
                splits.Add(new byte[cipher.Length / keylength]);

            var tail = cipher.Length % keylength;

            for (var i = 0; i < cipher.Length - tail; i++)
            {
                splits[i % keylength][i / keylength] = cipher[i];
            }

            return splits;
        }
    }
}
