using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography;
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

        public static string GetFileTextLines(string path)
        {
            using (var s = new StreamReader(path))
            {
                return s.ReadToEnd();
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
            var repeatingKey = Basic.ExpandKey(key, input.Length);
            return Xor(input, repeatingKey);
        }

        public static byte[] ExpandKey(byte[] key, int length)
        {
            var keyRepeat = new byte[length];
            for (var i = 0; i < length; i++) 
                keyRepeat[i] = key[i % key.Length];
            return keyRepeat;
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

        public static class Aes
        {
            // Massive help from:
            // http://cboard.cprogramming.com/c-programming/87805-%5Btutorial%5D-implementing-advanced-encryption-standard.html

            public static byte[] MSEncryptAes128Ecb(byte[] cihper, byte[] key)
            {
                using (
                    var aesAlg = new AesManaged
                    {
                        KeySize = 128,
                        Key = cihper,
                        BlockSize = 128,
                        Mode = CipherMode.ECB,
                        Padding = PaddingMode.Zeros,
                        IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
                    })
                {
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                    return encryptor.TransformFinalBlock(cihper, 0, cihper.Length);
                }
            }

            public static byte[] MSDecryptAes128Ecb(byte[] cipher, byte[] key)
            {
                using (
                    var aesAlg = new AesManaged
                    {
                        KeySize = 128,
                        Key = key,
                        BlockSize = 128,
                        Mode = CipherMode.ECB,
                        Padding = PaddingMode.Zeros,
                        IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
                    })
                {
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
                }
            }

            public static byte[] Encrypt(byte[] input, byte[] key)
            {
                if(input.Length%8 != 0 || input.Length < 16)
                    throw new Exception("Input must be byte array over 128 bits (in 64bit increments: 128, 192, 256, etc).");

                var len = input.Length;
                
                var expandedKey = Basic.ExpandKey(key, len);

                var state = Util.Blockify(input, 4, len/4);
                var keyBlock = Util.Blockify(expandedKey, 4, len / 4);

                throw new NotImplementedException();
            }

            public static byte[] DecryptAes128Ecb(byte[] cipher, byte[] key)
            {
                throw new NotImplementedException();
            }

            public static class Util
            {
                public static void AddRoundKey(ref byte[,] state, byte[,] key)
                {
                    var rows = state.GetLength(0);
                    var cols = state.GetLength(1);

                    if(key.GetLength(0) != rows || key.GetLength(1) != cols)
                        throw new Exception("State and Key must have similar dimensions.");

                    for (int i = 0; i < rows; i++)
                    {
                        for (int j = 0; j < cols; j++)
                        {
                            state[i, j] = Convert.ToByte(state[i, j] ^ key[i, j]);
                        }
                    }
                }

                public static void ShiftRows(ref byte[,] block, bool left = true)
                {
                    var rows = block.GetLength(0);
                    var cols = block.GetLength(1);

                    var temp = new byte[rows, cols];
                    Array.Copy(block, temp, rows*cols);

                    if (left)
                    {
                        for (int i = 0; i < rows; i++)
                        {
                            for (int j = 0; j < cols; j++)
                            {
                                block[i, j] = temp[i, (j + i)%cols];
                            }
                        }
                    }
                    else
                    {
                        for (int i = 0; i < rows; i++)
                        {
                            for (int j = 0; j < cols; j++)
                            {
                                block[i, j] = temp[i, (cols + j - i) % cols];
                            }
                        }
                    }
                }

                public static void SubBytes(ref byte[,] state, bool inverse = false)
                {
                    byte[] box;
                    if (inverse) box = new byte[]
                        {
                            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
                        };
                    else box = new byte[]
                        {
                           0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                           0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                           0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                           0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                           0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                           0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                           0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                           0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                           0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                           0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                           0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                           0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                           0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                           0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                           0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                           0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
                        };

                    for (int i = 0; i < state.GetLength(0); i++)
                    {
                        for (int j = 0; j < state.GetLength(1); j++)
                        {
                            state[i, j] = box[state[i,j]];
                        }
                    }
                }

                public static void MixColumn(ref byte[,] state)
                {
                    var magic = new byte[,] 
                    {
                        {2, 3, 1, 1},
                        {1, 2, 3, 1},
                        {1, 1, 2, 3},
                        {3, 1, 1, 2}
                    };

                    state = MultiplyMatrices(state, magic);
                }

                public static byte[,] Blockify(byte[] input, int rows, int columns)
                {
                    var len = input.Length;

                    var output = new byte[rows, columns];

                    for (var i = 0; i < len; i++)
                    {
                        output[i % rows, i / columns] = input[i];
                    }

                    return output;
                }

                public static byte[] Unblockify(byte[,] input)
                {
                    var rows = input.GetLength(0);
                    var cols = input.GetLength(1);

                    var output = new byte[rows * cols];

                    for (var i = 0; i < output.Length; i++)
                    {
                        output[i] = input[i%rows, i/cols];
                    }

                    return output;
                }

                public static byte[,] MultiplyMatrices(byte[,] m1, byte[,] m2)
                {
                    if(m1.GetLength(1) != m2.GetLength(0))
                        throw new Exception("Invalid matrix sizes.");

                    var rows = m1.GetLength(0);
                    var cols = m2.GetLength(1);
                    var inner = m1.GetLength(1);

                    var product = new byte[rows, cols];

                    for (int row = 0; row < rows; row++) {
                        for (int col = 0; col < cols; col++) {
                            // Multiply the row of A by the column of B to get the row, column of product.
                            for (int i = 0; i < inner; i++) {
                                product[row,col] = (byte)(m1[row,i] * m2[i,col]);
                            }
                        }
                    }

                    return product;
                }
            }
        }
    }
}
