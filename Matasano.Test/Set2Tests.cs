using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Matasano.Test
{
    [TestClass]
    public class Set2Tests
    {
        [TestMethod]
        public void TestS2C9()
        {
            const string message = "YELLOW SUBMARINE";
            const string answer = "59454c4c4f57205355424d4152494e4504040404";

            var paddedMessage = Basic.BytesToHex(BlockAndStream.Pad(Basic.AsciiToBytes(message), 20));

            Console.WriteLine(paddedMessage);
            Console.WriteLine(answer);
            Assert.AreEqual(answer, paddedMessage);
        }
    }
}
