using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace RSA.Cryptos.utils
{
    public static class Utility
    {
        public static BigInteger Generate16BitPrime(BigInteger? otherPrime = null)
        {
            BigInteger result = 4;// initialize to non prime number first
            var min = Convert.ToInt32("1000000000000000", 2);// minimum 16 bit integer
            var max = Convert.ToInt32("1111111111111111", 2);// maximum 16 bit integer
            var randomNumberGenerator = new Random();

            var condition = false;
            string exceptionMessage = string.Empty;
            var exceptionCounter = 0;

            while (!condition)
            {
                result = randomNumberGenerator.Next(min, max);
                try
                {
                    condition = otherPrime.HasValue
                        ? result.IsPrime() && result != otherPrime.Value && Math.Abs((sbyte)(result - otherPrime.Value)) != 2
                        : result.IsPrime();
                }
                catch (Exception e)
                {
                    exceptionCounter++;
                    exceptionMessage = e.Message;
                }

            }

            if (exceptionCounter > 0)
            {
                ShowSteps(exceptionMessage + $" {exceptionCounter} times", true);
            }

            return result;
        }

        public static bool IsPrime(this BigInteger n)
        {
            var t = (int)(n);

            if (n > 1)
            {
                return Enumerable.Range(1, t)
                    .Where(x => t % x == 0)
                    .SequenceEqual(new[] { 1, t });
            }

            return false;
        }

        public static List<BigInteger> StringToBigInteger(this string message)
        {
            //Assume that your message is "Hello World",
            //a.Divide your message into 3 - byte chunks, e.g., "Hello World"-> ["Hel", "lo ", "Wor", "ld"]
            var mArr = message.ChunksUpto(3).ToList();

            //b.Convert each chunk into a hexadecimal string, e.g., ["Hel", "lo ", "Wor", "ld"] ->
            //[0x48656c, 0x6c6f20, 0x576f72, 0x6c64]
            var mHexList = new List<string>();
            foreach (var m in mArr)
            {
                var charList = m.Select(x => x).ToList();
                var byteList = charList.Select(x => Convert.ToByte(x)).ToList();
                var hexList = byteList.Select(x => x.ToString("x")).ToList();
                var hexMessageRepresentation = string.Join("", hexList);
                mHexList.Add(hexMessageRepresentation);
            }

            //c.Convert each chunk into an integer number, e.g., [0x48656c, 0x6c6f20, 0x576f72,
            //0x6c64] -> [4744556, 7106336, 5730162, 27748]
            var BigIntegerArr = new List<BigInteger>();
            foreach (var mHex in mHexList)
            {
                var mInt = int.Parse(mHex, System.Globalization.NumberStyles.HexNumber);
                BigIntegerArr.Add(mInt);
            }

            return BigIntegerArr;
        }

        private static IEnumerable<string> ChunksUpto(this string str, int maxChunkSize)
        {
            for (int i = 0; i < str.Length; i += maxChunkSize)
                yield return str.Substring(i, Math.Min(maxChunkSize, str.Length - i));
        }

        public static void ShowSteps(this string step, bool showStep)
        {
            if (showStep) Console.WriteLine(step);
        }

        public static string BigIntegerToString(this List<BigInteger> integerMessageList)
        {
            var hexArr = new List<string>();
            integerMessageList.ForEach(x =>
            {
                var mHex = string.Format("0x{0:x16}", x);
                hexArr.Add(mHex.Substring(mHex.Length - 6).TrimStart(new Char[] { '0' }));
            });

            var message = string.Empty;

            var charList = new List<char>();
            hexArr.ForEach(x =>
            {
                for (var i = 0; i < x.Length; i += 2)
                {
                    var singleHex = x.Substring(i, 2);
                    int num = int.Parse(singleHex, NumberStyles.AllowHexSpecifier);
                    var mChar = (char)num;
                    message += mChar; 
                }
            });

            return message;
        }

    }
}
