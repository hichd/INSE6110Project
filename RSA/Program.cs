using Cryptos;
using RSA.Cryptos.utils;
using RSA.Profiles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            var errMsg = string.Empty;
            bool hasError = true;

            while (hasError)
            {
                hasError = false;

                try
                {

                }
                catch (Exception e)
                {
                    Console.Clear();
                    hasError = true;
                    errMsg += $"\n{e.Message}\nStack trace: {e.StackTrace}";
                    Console.WriteLine($"Error Messages:\n{errMsg}");
                    Console.ReadKey();
                }

                if (errMsg != string.Empty) Console.WriteLine($"Error Messages:\n{errMsg}");
            }

            Console.ReadKey();
        }

        private void ProjectSetup()
        {
            var partner = new PartnerData();
            var cipher = partner.GenerateEncryptedMessageForPartner("small message");
            Console.WriteLine(cipher);
            var myData = new MyData();
            myData.DecryptMyData(partner.CipherList);
            Console.WriteLine(myData.Message);
        }
    }
}
