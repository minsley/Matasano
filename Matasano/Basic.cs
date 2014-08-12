using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;

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
                {'z',0.00074}
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
    }
}
