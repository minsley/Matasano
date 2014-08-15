﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

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

            var inputByteArray = Basic.HexToBytes(input);
            var fixedXorByteArray = Basic.HexToBytes(fixedXor);

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
                var keyBytes = Basic.HexToBytes(key);
                var cipherTextBytes = Basic.HexToBytes(cipherText);

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
                    var score = Basic.IsLanguage(Basic.HexToBytes(line), Basic.EnglishCharacterFrequencies, out matches);
                    
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
                    var translation = Basic.XorRepeatKey(Basic.HexToBytes(cipher), new[] {key});
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
            var cipherBytes = Basic.Base64ToBytes(cipherText);

            // TODO REMOVE THIS
            //var cipherText = "1d2b2069362b282d2c242c303a63012c20292831243d2a2a27632a2f63312126653d2b2c3b37202c2d653c2d2c3d26216910312837203a632a2f630424263720202465142d2c2d65202d653d2b2069002a3c31362c632a2f632d3c2e242763203f262b3d3069692a316921202a2c282c30652726262c303628313c69252a3b632a27266539262a392f2069372a69272c3a302a25352069372d2c6335262f2c3d2a26282f652b222b2d30653e2b2c2a2b652122332c6326262d2b2c20312c27653d2b2024633220372d69222b26372d2c316969222b2d63312663243a3030242665282e2a2724653d2b2069332a3e26373a632a2f63312126652c22373d2b6969372d2c63362c33243b22312c63242727652c3230282f653a37243d2a2a276331266332212a262163312126650522323a632a2f630b2837303b2665282d21692c23690d243d36372c643669042a2d632027372c3d2f2069372d2c2e696922652d26262c2d316931203a33202a37653d2c653d2b20692c35202d2c262d36692c23692e2427282c2727653b26343c2a372c30653d2b243d633121263c69302d2636292d63212c202928312069372d2c63262836362c30653e2b2c2a2b65202e352c2f653d2b202463312663312126653a26352831243d2a2a276d122c632d262f2169372d2c30206937373c372d3a63312663272c63362c2f2364263320272027376969372d283765282f29692e202763243b26652a31202837202d6320383624256f653d2b243d633121263c6922372c632027272a3e262169213c69372d2c2a376900372c22312631653e2a312163262c3131282a2b69362b282f2c2c2d242b2f2069112c2e2b313a6f653d2b243d6324242c2b2e63312126362c63243b2665052a232c6f65052a272c31313063242727653d2b206933303b3030203765262565012235392a2b2c3036676e681d2b243d63312663362c20303b26653d2b203a26653b2a222137366563022635203b2d282c2d313a63243b2665202d363d2a313c37202d6324242c2b2e63082c2d696927203b2a33202d2269372d2c2a376929303a3765392c322c3136692537262e653d2b2069202a2730202737652625653d2b2069242a3f263727262165636864172d2837653e2b202726332c3165282d3c69052a3b2e652625650e2c332c312b24262b3d63272c202a2426366927203a37373c2031203520692c2369372d2c302069262b2d3069692a31692a3669372d2c631720242d3d632a2f633121266519262a392f2069372a6922293d2637692c3769372a692227262f2c3a2b6520376969222b2d633126632c2730312037303d266527263269042a3f2637272e20273769692f24302a2b2e632c3d30652f2c302727243d2a2a27632a2763363c202d693337202d262033292c3065282d21692c372e222b20392c27246520373669332a3e26373a632c2763363c202d69252a3b2e6969223669372a69372d2c2e653a2b24252f653a2620246328263031692f2c2226293063312663202f25202a37653d2b202031651a22232c373c69222b2d630d283335202d203a306b6913373c272027202065632c2727202c276969342c252f652d2a263d22312c633121223169042a3f2637272e20273736692f2a2724652c303128212920302d2c27653a2b2a3c2f21692d2a3d63272c632621222b2e262169252a3b632920242d3d63242727653d312427302c2c2d316920243c30203a7865282d216922262a2c372d2a2b2e2f3c6922292563203133203b2a20272020692b243d2b653a2b203e2d6969372d28376524222b222a2b2d63243b2665242c372c63212030352630202d63312663363c25232c316969342d202f20692633202f366922372c63363c25232c31242b2f2065633121222b69372a69312c2e2b3169372d2c2e362c2f332c30652b3a6528212a252a36212a2b2e63312126652f2c372430653d2c653e2b2c2a2b653d2b203063243b26652820263c3031262e202d6d650b363169342d2c2d65286329262d22693737282a2b692c236922273c30203a63242727653c30303b33243d2a2a2730696933303b3030202d22692a2b3f2237202227253a653d2b2069302424266506212f2c2031692633202d262c30652863212c302c2e2d653d2c653b26213c202069372d2c2e653c2d212c3165282136262f303d26650d2636392c3120302865632c3d632c3a633121262c3b633720242d3d6f652037652030653d2b202031652d3631306f653d2c653d2b372634652625236930302a2b650e2c332c312b24262b3d6f65282d2169372a69333726352c2d26652726326904302831213a63232631653d2b202031652f36313c31206930202a363720373c676e681a362621632d2830652b262027633121266539223120262b3d63363c25232c3124272020692c2369372d2c302069002a252c2b2026367263242727653a362621632c3a632b2634653d2b20692d202a26363a2a31306332212a26216326262d363d3124202d3669372d2c2e653d2c65282f312c31653d2b202031652f2c3724263769103c3a37202430652625650e2c332c312b24262b3d6d651d2b20692b2c3a372a3b3a652625653d2b206933372c3020273765022a2b2e632a2f63023b26243d63073b2a31282a2b692a36692265212a363d2c3730632a2f63372c33202837202d632c2729303b2a203a63242727653c30303b33243d2a2a27306969222925632d28352c272465202d652d2a372c2031692c272326263d63312126652c303128212920302d24262b3d632a2f63242763242b302a2536312c6311303124272d3c692c332c31653d2b203a26651a37243d26366763112663353b2c332c6331212a366563292c37650f22263d30652b26653a3627242a313d262169372a6922652a222b2d2a2169342a3b2f2167636569630d2c632d2830653b26233c30202d632d2030650830362c2d3169372a690f243e306969372d2c632826303169342d262f203a2c282c63242727652726262c303628313c69252a3b6331212665393627252a2669242a26276b696365690b20692b243a63232631272027212c2d65212a3669042a3f2637272c373a6331266335283036690f243e3065262565202e282c272c28372069222b2d63353b26363a2a2b2e632c24332a3b3724272020656330272f203a30653a363639262b2d2621692a2b69372d2c2a37692c352c31243d2a2a276331202f29692b2c3a63043a30202737653a2b2a3c2f21692120692c273d222c2726217263242727653e2b202763362663363c30352c2d212c2769692b20692b243a63303d37203b2f3c692d202e2f202a37202d63312663243d37202727653d2c653d2b20246d656963650126652122366931202f36362c27653d2c653922363a632a3d2b203b630928343669252a3b6331212665282026262e282627243d2a2a27632a2f63292831222c63212030313b2a263d306526256539262a392f20656330272f203a30653d2b2a3a266539262a392f2069342a3c2f21693120252a2b38362c3a2b653d2b2069312c2e2b31692c236911203931203a262b3d2231202c2b692a2b69372d2c63092c242c3a2f243d36372c6f6528633720242d3d632c2726363d2a282821292c633126633121262869222b2d63232631282027242b2f2069372a69373c3b222b3d3065262d29306d65696365012665212236692024252f202d63312624203d2b203b63292c242c3a2f243d2a332c632726272c2c3065283765392f242a263669362b3c3030282f6969362b2a2c282f2c373d222725266969222b2d6321203031282d31692537262e653d2b20692720392c3620372a3b3a652625653d2b20203165393627252a266911202a2c372d306969252a3b63312126653a2c292c63353c3135263020692c236925243d2a223c2a2b2e6331212628692a2b3d2c652a2c28392f2c282d262c633220372d692b2c3a63282c22363c31203a6d6569636501266521223669272c3a302a2535202d63172c33372c30202737243d2a332c630d2636362c30653b26352c22312c2729306f652f2c37692c35392c36202d2269342c3d2b6524222b253a652f2a37242d203a3065212a36692a2b3f2236202c2b3a632a2763312126653b2a22213736692c2369372d2c63352c2c3525266b696365690b20692b243a63372c25303a262169252a3b6324692f2a2724653d2a282c6f652825312c31653a3626216321203036262f303d2a2a27306969372a6920243c3020692c312126373a63312663272c63202526263d26217263322126372c213c69372d2c63092c242c3a2f243d2a332c63352634203b3069692a2b2a22352821292c632a2f6304272d2c212a2928372c262d69692b243f26653b26313c312b2c27653d2c653d2b206913202633292c63243d63292831222c63232631653d2b202031652c3b203b202c3a267e69372d2c63163d22312c63372c2e24202d2c272465202d653d2b20692e20282d653d2a282c632031332a3a262169372a6922292563312126652d222b2e26373a632a2f632c2735243a2a2a2763233b2c2869342c3d2b2a3c376969222b2d6326262d333c2f36202c2b3a633220372d202d6b696365690b20692b243a632027272028352a3c31202d63312663353b26332c2d3169372d2c6335263330252231202c2b692c2369372d2c30206910312837203a78652f2c3769372d283765393637392c362c632a2b30313b36263d2a2b2e63312126650522323a63232631650722313c3124252a3f28372c262d652625650f2c372c2a222726373a78653b26233c302c2724653d2c653922363a632a3d2b203b30653d2c652c2d2626363728242069372d2c2a37692e2c2e31243d2a2a273065212a312126376563242727653b222c3a2a2b2e63312126652a2c2b2d2a31202c2b3a632a2f632b2c34650833353b2c353b2a243d2a2a27306526256505222b2d306b696365690b20692b243a632a2b30313b36263d262169372d2c63042d2e2c272a363d31243d2a2a27632a2f630f3c30312020206563273063372c25303a2a2b2e632d2030650830362c2d3169372a690f243e30652f2c376926363d2227252a36212a2b2e630f3c272c2a2a243b3a65392c322c313667636569630d2c632d2830652422212c630f3c27222c30652d26352c2d212c2d31692c2b692b2c3a6312202f29692229262d206563232631653d2b206937202736372c632a2f633121262c3b632a2f252c2a26366563242727653d2b2069222826362b3d632427276539223c24262b3d632a2f633121262c3b6336282f243b2a203a6d656963650126652122366926372c20312c27652863283c2f312037302d2665262565072632690c232f2a262c306969222b2d63362c2d31692b2c3d2b203b63363e22372430652625650625232020203b30653d2c652122373b22363a632a3c316539262a392f206563242727652c2231692c303d633121262c3b63363c21363d222b2a266b696365690b20692b243a632e2c3331692228262d2269363665632c276331202e203a632a2f63352c22262c6f651a372427272c27246508312820263669342c3d2b2a3c37653d2b2069002a273020273765262565263637692f202e2a362522313c31203a6d656963650126652122366922232f26263d262169372a6931202727203b6331212665042a292037243b3a65202d212c3320272720273765262565282d21693030392637202c3769372a69372d2c630620352c2563352634203b6d6569636501266521223669202a24212c27262169342c3d2b6526372d2c313669372a6930302b29202a37653c30653d2c6528632f3c312c3a272c2a372c262d652f2c372c2a2227633126632a3c31652a2c2b3a372c3d3631202c2b6563242727653c2d242a282b2634292c27222c27652b3a65263637692f243e307e69242c3f2a2b2e632d2030650830362c2d3169372a69372d2c2a376902263d30652625653931203d262b2d2621690f202e2a36252231202c2b7363656963032631651836243b37203b2a2b2e63292831222c632726272c2c30652625652831282c27653d312a263336692228262d2269363673636569630326316539312a3d26263d2a2b2e6331212628656327306324692e2a2a28651d312c282f69692537262e6539362b20302d24262b3d6323263165282d3c690e303b27203b30653e2b2c2a2b653d2b20306336212c302527652a2c28242a31692c2b69372d2c630c272b242b2a31282d313a632a2f63312126362c63163d22312c307f69636569052a3b63263c3731202d22692c232f632a3c31651d31242d26653e2a31216324252f653922373d30652625653d2b2069342a3b2f21736365696303263165202e3526302c2724651d223d2c3065262d653c30653e2a31212c303d632a3c31650a2c2b3a262b3d79656963650f2c3769272039312c3f2a2b2e63303a632c276328282d3c6920243a263665632a2f63312126652b262b2c252c3d30652625651d312c282f652b3a650336373079656963650f2c37693737282d36392c373d2a2b2e63303a63272c3a2a2727651a26243a63312663272c63313b2a202d63232631653931203d262b2d2621692c232f262b2a263669636569052a3b63242b2c2920302d202d2269372d2c63233b262069103c3a372024632a2f630027242920302d690f243e3065202d6528632b2c2a2221212a3c312c27246519312a3f2a2b2a26696926363d2227252a36212a2b2e63312126372c2a2b69222b6902372b2a313b22373063222635203b2d282c2d316563242727652c2d29283122202d22692a313a630726362b2d223720263669302a69223669372a6931202727203b632c3d63243d632a27202069222b69263d282e35252665282d2169252c3d632c2730313b36282c2d3169252a3b632c2737372627302a2a2b2e63312126653a22282c63242b302a2536312c63373c2f20692a2b3d2c653d2b203a26650a2c29262d2c2c307f69636569052a3b633128282c27246528342430632a3c31650a2b243b37203b3069692227262f2c3a2b2c272465263637692e2a3a37653f22293c22272526650522323a6f65282d216922293d2637202d2269253027272424262b3d2229253a653d2b2069052a3b2e36692c23692c303b63022635203b2d282c2d313a79656963650f2c376930303a332027272c272465263637692c322763092c242c3a2f243d36372c306969222b2d63212c202928312c2724653d2b202430202535203a632c2735203a37202d633220372d69332a3e263769372a692f202e2a362522312c63232631653c3065202d65282f296920243a263669342d2837362626332c316b696365690b20692b243a63242b272c2a22312c27650e2c332c312b24262b3d632d2c31206563273063212c202928312c2724653c3065263631692c23692b2c3a63153b2c312c2031202c2b69222b2d633228242c2724651e2237692222282a2b3a37653c306b696365690b20692b243a633525362b2d26372c27652636376930202830696931243f22222c276526363769002a2830313a6f652b363727376526363769372a3e2d366563242727652d26363d312a30262169372d2c63292035203a632a2f632a3c316539262a392f2067636569630d2c632c3a63243d6331212a3669372c2426653d3124273035263131202d22692f243b2420690237242a203a632a2f632326312020242b690e203b202027223720263669372a69202a2433292c223169372d2c633226312e3a632a2f63212c2231216f652d2636262f243d2a2a2763242727653d3a37282d2b306f65282f372c22213063272c243027633220372d69202c3b2030243031282d262c30652625650a31302c2f313063636933203b252c2d3a653a20243b2020253a65392237282f292c2f202d632c276331212665242c363d632728312728312a3c30652824203a6f65282d2169372a3d2229253a653c2d32263131213a653d2b20690b2028276526256528632620352c252a3f2c2765272231202c2b67636569630d2c632d2830652a2c2b3a3737282a2b2c2765263637692520252f2a3e630620372c33262b3a6331282820276306283331203520692c2b69372d2c632d20242d6910202830653d2c652b26243b63043b2e36692222282a2b3a37653d2b202031650a2c30273737306f653d2c652b2626262e2069372d2c63203126263c372c262d203b30652625653d2b202031652f312c2c2d213a63242727650b31203d2b372c2d69692c3769372a692524252f653d2b202430202535203a632730633121262c3b630d282d213a6d6569636501266521223669263d2a2a312c27652d2c282c3031202065202d363c31372c2031202c2b3a6324242c2b2e303169363665632427276521223669262b2d26243f2c303b262169372a692137202d22692c2b69372d2c632c272b242b2a31282d313a632a2f632a3c31652f312a27372c2c31366563312126652426372a2a292c3036690a2b2d2a242763162835242e2636656332212c362c632e272c322763373c2f20692c236934243b25243b2669692a3669222b69362b2d2a363d2a2b2e362c3a2b202d63212c30313b36263d2a2a27632a2f6324252f652824203a6f653a263d2c3065282d2169202a27272c3d2a2a27306b002d652c35203b3a653a37242e26652625653d2b203a26650633353b26363a2a2a2730651e26652122332c63152c372c3d2a2a27262169252a3b63172c27372c3036692a2b69372d2c6328263031692b302421292c63312c31283a79650636376931203926243d26216913203d2a31202c2b3a632d2835206921202c2d65282d363e26372c2765262d293063273063372c33202837202d632c2729303b3a6b69026519312c27202069342d26302069202d2831242a37203b632c3a6331213636692e243b28202d63273063203f26373063242a37653e2b2c2a2b6524223c6927202f2a2b2c632469173c3b222b3d6f652030653c2d232037653d2c652b26653d2b20693130252637692c236922652f31202c63352c2c3525266b072c37692b243f26651e26652b2620276332282d31202d22692a2b6922313d262b3d2a2a2730653d2c6526363769013720373120302d6921372c372d3b262b6763122c632d2835206934243b2d202d6331212628692537262e653d2a282c6331266331202e20692c236922313d262839373669213c69372d2c2a37692f202e2a362522313c312069372a69263d3d262b2d63242763302734243b31242737242b2f206929303b2a362d2a263d2a2a27632a3f26376936366763122c632d283520693120242a2b2d262169372d2c2e652625653d2b2069202c3b2030243031282d262c306526256526363769262820243728372c262d65282d216930203d37292c2e202737652126372c6d651e26652122332c6324393320282f202d633126633121262c3b632b28372c3f26652336363d2a262c632427276524222227222b202e2c3d3a6969222b2d63322c632d28352069202a2729303b262169372d2c2e652b3a653d2b2069372c2c306526256526363769202a242e2a27632e202d213b262169372a69272c3a22332634653d2b203a26653c30303b33243d2a2a27306969342d20202d6563322636292d632c2726332037242b2f3c692a2b3d26373b36353d632a3c31652a2c2b2726263d2a2a273065282d2169202a3b31203a332a27272027202067631121263c69372a26632d2835206921202c2d652d26242f63312663312126653f2c2c2a26652625652336363d2a262c63242727652625652a2c2b3a222b2e362c272a31306d651e26652436363d6f653d2b203b26232631206563242a32302026362a2665202d653d2b20692d202a26363a2a31306f653e2b2c2a2b652d262b26362b2a2636692c303b63162c33243b2231202c2b656324272765212c292d63312126286563243a63322c632d262f2169372d2c63372c3031692c23692e2427282c27276969062b2c2e2c2c3065202d651e223765632c2763152c22262c63033b2a202727366714206563312126372c252a3b266969372d2c63172c33372c30202737243d2a332c30652625653d2b2069362b2037202d63163d22312c3065262565082e203b2a26286f65202d650e262b2c3124256306262d223b26363a6f650830362c2e27252621656324393320282f2c2724653d2c653d2b206910303931202426650336212e26652625653d2b2069342a3b2f2169252a3b63312126653b26263d2a313c2720692c23692c303b632c27372027372c262d36656321266f65202d653d2b20690d2424266969222b2d63273063043c372d26312c3d3a652625653d2b2069242a26276519262a392f20692c2369372d2c302069002a252c2b202636656336262f20242d293063353c212920302d69222b2d63212c202928312065631121223169372d2c302069162b2037202d6306262f2a272a203a63243b266969222b2d632a2f631720242d3d632a3c242d3d63312663272c63033b262069222b2d630c27272039262b2d262b3d63163d22312c307e69372d2837653d2b203063243b2665082136262f332c27652f312a246324252f65082f292c242c282d262c63312663312126650b312c3d2a362163063b2c32276f65282d2169372d283765282f2969332a252a31202024256326262d2b2c2031202c2b6921203d34202c2d653d2b202463242727653d2b20691031283720692c236904372c2231690137203724202d69692a3669222b2d632a3c242d3d63312663272c6331263724252f3c69272c3a302a2535202d7865282d2169372d2837652830650f31202c6324272765002d212c33202727202737651a37243d263665633121263c692b243f26652f36292563152634203b63312663292c353c6914243b6f652a2c2b2a2f302d26651926242a266969202a273737282031690229252a242720203a6f652c303128212920302d69002a242e203b20206563242727653d2c652d2c65282f29692c312126376902263d3065282d2169172d202d223a6332212a2621630c27272039262b2d262b3d63163d22312c306524223c692c2369312c2e2b3169272a6763042727652f2c3769372d2c63363c3335263131692c2369372d2030650d262625223728372c262d6969342c3d2b65286323203128693120252a24272020692c2b69372d2c63353b2c312c2031202c2b692c2369272c3f2a2b2c63153b2c332027202720206563322c63283c3730282f293063352526212e26653d2c652c222621632a3d2b203b632a3c3165052a332c3069692c303b63032631313c2d203a63242727652636376930242a31202d630d262d2a3b6d";
            //var maxKeysize = 3;
            //var cipherBytes = Basic.HexToBytes(cipherText);

            var keysize = Basic.GetKeysize(cipherBytes, maxKeysize, 8);

            var cipherBlocks = Basic.GetRepeatKeySplit(cipherBytes, keysize);

            const int numKeysToTry = 4;

            var keys = new List<byte[]>();
            for (var i = 0; i < numKeysToTry; i++)
                keys.Add(new byte[keysize]);

            for (var i=0; i < cipherBlocks.Count; i++)
            {
                List<Tuple<double, byte, char>> matches;
                Basic.IsLanguage(cipherBlocks[i], Basic.EnglishCharacterFrequencies, out matches);

                var keyBytes = Basic.GetKeysFromLanguageMatches(matches, numKeysToTry);
                for (var j=0; j < keyBytes.Count(); j++)
                    keys[j][i] = keyBytes[j];
            }

            var snippet = new byte[200];
            Array.Copy(cipherBytes, snippet, 200);

            var bestKey = new byte[keysize];
            double mostEnglish = 0;
            foreach (var key in keys)
            {
                var messageBytes = Basic.XorRepeatKey(snippet, key);
                var englishLikeness = Basic.IsEnglish(messageBytes, Basic.EnglishCharacterFrequencies);
                if (englishLikeness > mostEnglish)
                {
                    mostEnglish = englishLikeness;
                    bestKey = key;
                }
            }

            Console.WriteLine(Basic.BytesToAscii(Basic.XorRepeatKey(cipherBytes, bestKey)));
        }

        [TestMethod]
        public void TestS1C7()
        {
            const string key = "YELLOW SUBMARINE";
            const string path = @"..\..\Assets\S1C7.txt";

            var input = Basic.Base64ToBytes(Basic.GetFileText(path));
            var keyBytes = Basic.AsciiToBytes(key);

            var message = Basic.DecryptAes128Ecb(input, keyBytes);

            Console.WriteLine(Basic.BytesToAscii(message));
        }

        [TestMethod]
        public void TestS1C8()
        {
            /* Strategy:
             * 1. For each ciphertext, break into 128bit blocks
             * 2. Look for repeating blocks (identical plaintext will produce identical ciphertext under ecb)
             */

            const string path = @"..\..\Assets\S1C8.txt";

            var cipherText = Basic.GetFileTextLines(path);

            var mostRepeats = 0;
            var possibleEcb = "";
            foreach (var cipher in cipherText.Split('\n'))
            {
                var blocks = new Dictionary<string, int>();
                for (int i = 0; i < cipher.Length; i+=16)
                {
                    var block = cipher.Substring(i, 16);
                    if (blocks.ContainsKey(block)) 
                        blocks[block]++;
                    else
                        blocks.Add(block, 1);
                }

                var repeats = blocks.Sum(x => x.Value);
                if (repeats > mostRepeats)
                {
                    mostRepeats = repeats;
                    possibleEcb = cipher;
                }
            }

            Console.WriteLine("{0} repeating blocks were found.\nThe ECB cipher is probably:\n\n{1}",mostRepeats , possibleEcb);
        }
    }
}
