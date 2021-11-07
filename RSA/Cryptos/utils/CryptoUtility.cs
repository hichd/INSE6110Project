using System;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace RSA.Cryptos.utils
{
    public static class CryptoUtility
    {
        private static Queue EuclideanAlgorithm(BigInteger a, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"___ Euclidean Algorithm BGEIN ___", showSteps);

            var dividend = n;
            var divisor = a;
            BigInteger remainder = 0;
            var quotientQueue = new Queue();

            while (remainder != 1)
            {
                var quotient = (BigInteger) Math.Truncate((double)dividend / (double)divisor);
                remainder = dividend - (quotient * divisor);
                Utility.ShowSteps($"{dividend} - ({divisor} * {quotient}) = {remainder}", showSteps);
                dividend = divisor;
                divisor = remainder;
                quotientQueue.Enqueue(quotient);
            }

            Utility.ShowSteps($"___ Euclidean Algorithm END ___", showSteps);

            return quotientQueue;
        }

        private static BigInteger ExtendedEuclideanAlgorithm(BigInteger a, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"+++ Extended Euclidean Algorithm BEGIN +++", showSteps);
            BigInteger result = 0;
            BigInteger b = 0;
            BigInteger c = 1;

            var quotientQueue = EuclideanAlgorithm(a, n, showSteps);

            while (quotientQueue.Count > 0)
            {
                var quotient = (BigInteger)quotientQueue.Dequeue();
                result = b - (c * quotient);
                Utility.ShowSteps($"{b} - ({quotient} * {c}) = {result}", showSteps);
                b = c;
                c = result;
            }

            Utility.ShowSteps($"({a}^-1) mod {n} = {result}", showSteps);
            if (result < 0) result += n;
            Utility.ShowSteps($"+++ Extended Euclidean Algorithm END with ({a}^-1) mod {n} = {result} +++", showSteps);

            return result;
        }

        public static BigInteger ModInverse(this BigInteger a, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"<<<<<<<<<<<<< Multiplicative Modular Inverse BEGIN, {a}^-1 mod {n} >>>>>>>>>>>>>>>>", showSteps);
            var result = ExtendedEuclideanAlgorithm(a, n, showSteps);
            return result;
        }

        public static BigInteger GreatestCommonDivisor(BigInteger a, BigInteger b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            var result = (int)(a) | (int)(b);
            return result;
        }

        public static BigInteger SquareAndMultiply(BigInteger m, BigInteger e, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"================== Square And Multiply BEGIN, computing ({m}^{e}) mod {n} ==================", showSteps);
            // binary representation of e
            var stringArr = Convert.ToString((int)e, 2).ToCharArray();
            Array.Reverse(stringArr);
            string eBinary = new string(stringArr);
            Utility.ShowSteps($"exponent = {e} in binary : {eBinary}", showSteps);
            var maxExponent = eBinary.Length - 1;

            var exponentResultDictionary = new Dictionary<int, BigInteger>();

            BigInteger result = 1;
            var exponentiationResult = m;

            for (var exponent = 0; exponent <= maxExponent; exponent++)
            {
                if (exponent != 0)
                {
                    var squared = exponentiationResult * exponentiationResult;
                    exponentiationResult = squared % n;
                }

                exponentiationResult %= n;

                exponentResultDictionary.Add(exponent, exponentiationResult);

                if (eBinary[exponent] == '1')
                {
                    result *= exponentiationResult;
                }

                Utility.ShowSteps($"({m}^{Math.Pow(2, exponent)}) mod {n} = {exponentiationResult}, {eBinary[exponent]} <-- 2^{exponent}", showSteps);
            }

            Utility.ShowSteps($"{result} mod {n}", showSteps);
            result %= n;
            Utility.ShowSteps($"================== Square And Multiply END, ({m}^{e}) mod {n} = {result} mod {n} = {result}  ==================", showSteps);
            return result;
        }

        public static BigInteger RsaPhiFunction(BigInteger p, BigInteger q)
        {
            var a = p - 1;
            var b = q - 1;
            BigInteger result = a * b;
            return result;
        }

        public static BigInteger GenerateRsaPublicExponent(this BigInteger phiOfN)
        {
            BigInteger e = 4;// initialize to non prime number first
            var condition = false;
            var randomNumberGenerator = new Random();

            while (!condition)
            {
                e = randomNumberGenerator.Next(999);
                condition = e.IsPrime() && e < phiOfN && GreatestCommonDivisor(e, phiOfN) == 1;
            }

            return e;
        }
    }
}
