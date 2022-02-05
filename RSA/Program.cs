using Cryptos;
using RSA.Cryptos;
using RSA.Cryptos.utils;
using System;
using System.Numerics;
using utils;

namespace RSA
{
    class Program
    {
        static void Main(string[] args)
        {
            bool hasError = true;

            while (hasError)
            {
                hasError = false;

                try
                {
                    Utility.ProjectSetup();
                }
                catch (Exception e)
                {
                    hasError = true;
                    Utility.HandleErrors(e);
                }
            }

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }
    }
}
