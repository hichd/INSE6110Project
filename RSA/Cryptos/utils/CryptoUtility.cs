using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using utils;

namespace RSA.Cryptos.utils
{
    /// <summary>
    /// Modular arithmetics and cryptographic operations utility provider
    /// </summary>
    public static class CryptoUtility
    {
        #region GCD, Euclidean algorithm
        /// <summary>
        /// simple Implementation of greatest common divisor
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Elaborate implementation of greatest common divisor with steps to use for extended euclidean algorithm
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        public static (BigInteger gcd, Queue quotientQueue) EuclideanAlgorithm(BigInteger a, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"                          ___ Euclidean Algorithm BGEIN, GCD({a},{n}) ___", showSteps);

            BigInteger gcd = 1;

            var dividend = n;
            var divisor = a;
            BigInteger remainder = 0;
            var quotientQueue = new Queue();

            while (remainder != 1 && divisor != 0)
            {
                var quotient = (BigInteger) Math.Truncate((double)dividend / (double)divisor);
                remainder = dividend - (quotient * divisor);
                Utility.ShowSteps($"                          {dividend} - ({divisor} * {quotient}) = {remainder}", showSteps);
                gcd = remainder == 0
                    ? divisor
                    : remainder;
                dividend = divisor;
                divisor = remainder;
                quotientQueue.Enqueue(quotient);
            }

            Utility.ShowSteps($"                          ___ Euclidean Algorithm END, GCD({a},{n}) = {gcd} ___", showSteps);

            return (gcd, quotientQueue);
        }

        /// <summary>
        /// Implementation of extended euclidean algorithm with steps
        /// </summary>
        /// <param name="a"></param>
        /// <param name="n"></param>
        /// <param name="showSteps"></param>
        /// <returns></returns>
        public static BigInteger ExtendedEuclideanAlgorithm(BigInteger a, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"                   +++ Extended Euclidean Algorithm BEGIN +++", showSteps);
            BigInteger result = 0;
            BigInteger b = 0;
            BigInteger c = 1;

            var quotientQueue = EuclideanAlgorithm(a, n, showSteps).quotientQueue;

            while (quotientQueue.Count > 0)
            {
                var quotient = (BigInteger)quotientQueue.Dequeue();
                result = b - (c * quotient);
                Utility.ShowSteps($"                   {b} - ({quotient} * {c}) = {result}", showSteps);
                b = c;
                c = result;
            }

            Utility.ShowSteps($"                   ({a}^-1) mod {n} = {result} mod {n}", showSteps);
            if (result < 0) result += n;
            Utility.ShowSteps($"                   +++ Extended Euclidean Algorithm END with ({a}^-1) mod {n} = {result} +++", showSteps);

            return result;
        }
        
        /// <summary>
        /// Implementation of modular multiplicative inverse with steps
        /// </summary>
        /// <param name="a"></param>
        /// <param name="n"></param>
        /// <param name="showSteps"></param>
        /// <returns></returns>
        public static BigInteger ModInverse(this BigInteger a, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps($"      <<<<<<<<<<<<< Multiplicative Modular Inverse BEGIN, {a}^-1 mod {n} >>>>>>>>>>>>>>>>", showSteps);
            if (a > n || a < 0)
            {
                var old_a = a;
                a = a % n;
                Utility.ShowSteps($"modular reduction before starting extended euclidean algorithm : ({old_a}^-1) mod {n}  = ({a}^-1) mod {n}", showSteps);
            }
            var result = ExtendedEuclideanAlgorithm(a, n, showSteps);
            Utility.ShowSteps($"      <<<<<<<<<<<<< Multiplicative Modular Inverse END, {a}^-1 mod {n} = {result} >>>>>>>>>>>>>>>>", showSteps);
            return result;
        }
        #endregion 

        /// <summary>
        /// Implementation of the square and multiply algorithm for equation of the form (m^e) mod n
        /// </summary>
        /// <param name="m"></param>
        /// <param name="e"></param>
        /// <param name="n"></param>
        /// <param name="showSteps"></param>
        /// <returns></returns>
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
            var multiplicationElements = new List<BigInteger>();

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
                    multiplicationElements.Add(exponentiationResult);
                    result *= exponentiationResult;
                }

                Utility.ShowSteps($"({m}^{Math.Pow(2, exponent)}) mod {n} = {exponentiationResult}, {eBinary[exponent]} <-- 2^{exponent}", showSteps);
            }

            var multiplicationRepresentation = string.Join(" * ", multiplicationElements.Select(x => x.ToString()).ToArray());

            Utility.ShowSteps($"{result} mod {n}", showSteps);
            result %= n;
            Utility.ShowSteps($"================== Square And Multiply END, ({m}^{e}) mod {n} = {result} mod {n} = {multiplicationRepresentation} mod {n} = {multiplicationElements.Aggregate((a, x) => a * x)} mod {n} = {result}  ============", showSteps);
            return result;
        }

        /// <summary>
        /// Calculates phi(N) = (p - 1) * (q - 1)
        /// </summary>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <returns></returns>
        public static BigInteger RsaPhiFunction(BigInteger p, BigInteger q)
        {
            var a = p - 1;
            var b = q - 1;
            BigInteger result = a * b;
            return result;
        }

        #region CRT
        public static BigInteger ChineeseRemainderTheorem2(BigInteger a1, BigInteger n1, BigInteger a2, BigInteger n2)
        {
            Console.WriteLine("{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{Chinese remainder theorem BEGIN CRT 2 equations}}}}}}}}}}}}}}}}}}}");
            var modInv1 = ModInverse(n2, n1);
            var modInv2 = ModInverse(n1, n2);
            var X = (a1 * n2 * modInv1 + a2 * n1 * modInv2) % (n1 * n2);
            Console.WriteLine($@"

            X = {a1} mod {n1}
            X = {a2} mod {n2}

        X = [ {a1}*{n2}*(({n2}^-1) mod {n1}) + {a2}*{n1}*(({n1}^-1) mod {n2}) ] mod {n1}*{n2}
        X = [ {a1}*{n2}*({modInv1}) + {a2}*{n1}*({modInv2}) ] mod {n1}*{n2}
        X = [ {a1 * n2 * modInv1} + {a2 * n1 * modInv2} ] mod {n1}*{n2}
        X = ({a1 * n2 * modInv1 + a2 * n1 * modInv2}) mod {n1 * n2}
        X = {X}

                    Check answers : 
                                {X} mod {n1} = {a1} mod {n1} : {X%n1 == a1%n1}
                                {X} mod {n2} = {a2} mod {n2} : {X%n2 == a2%n2}
        ");

            Console.WriteLine($"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ Chinese remainder theorem 2 END with X = {X} }}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}");

            return X;
        }

        public static BigInteger ChineeseRemainderTheorem3(BigInteger a1, BigInteger n1, BigInteger a2, BigInteger n2, BigInteger a3, BigInteger n3)
        {
            Console.WriteLine("{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{Chinese remainder theorem BEGIN CRT 3 equations}}}}}}}}}}}}}}}}}}}}}}}");
            var modInv1 = ModInverse(n2*n3, n1);
            var modInv2 = ModInverse(n1*n3, n2);
            var modInv3 = ModInverse(n1*n2, n3);
            var X = (a1 * (n2 * n3) * modInv1 + a2 * (n1 * n3) * modInv2 + a3 * (n1 * n2) * modInv3) % (n1 * n2 * n3);
            Console.WriteLine($@"

            X = {a1} mod {n1}
            X = {a2} mod {n2}
            X = {a3} mod {n3}

        X = [ {a1}*({n2}*{n3})*((({n2}*{n3})^-1) mod {n1}) + {a2}*({n1}*{n3})*((({n1}*{n3})^-1) mod {n2} + {a3}*({n1}*{n2})*((({n1}*{n2})^-1) mod {n3}) ] mod {n1}*{n2}*{n3}
        X = [ {a1}*({n2 * n3})*((({n2 * n3})^-1) mod {n1}) + {a2}*({n1 * n3})*((({n1 * n3})^-1) mod {n2} + {a3}*({n1 * n2})*((({n1 * n2})^-1) mod {n3}) ] mod {n1}*{n2}*{n3}
        X = [ {a1}*({n2 * n3})*({modInv1}) + {a2}*({n1 * n3})*({modInv2}) + {a3}*({n1 * n2})*({modInv3}) ] mod {n1}*{n2}
        X = [ {a1 *( n2 * n3)}*({modInv1}) + {a2 *(n1 * n3)}*({modInv2}) + {a3*(n1 * n2)}*({modInv3}) ] mod {n1}*{n2}
        X = [ {a1 * (n2 * n3) * modInv1} + {a2 * (n1 * n3)*modInv2} + {a3 * (n1 * n2)*modInv3} ] mod {n1}*{n2}
        X = [ {a1 * (n2 * n3) * modInv1 + a2 * (n1 * n3) * modInv2 + a3 * (n1 * n2) * modInv3} ] mod {n1 * n2}
        X = {X}

                    Check answers : 
                                {X} mod {n1} = {a1} mod {n1} : {X % n1 == a1 % n1}
                                {X} mod {n2} = {a2} mod {n2} : {X % n2 == a2 % n2}
                                {X} mod {n3} = {a3} mod {n3} : {X % n3 == a3 % n3}
        ");
            Console.WriteLine($"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ Chinese remainder theorem 3 END with X = {X} }}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}");

            return X;
        }
        #endregion

        /// <summary>
        /// Randomly selects public prime exponent e such that e < phi(N) and e and phi(N) are relative prime numbers
        /// e's value is limited to 999 in order to speed up encryption operations and still resist to low exponent attacks
        /// </summary>
        /// <param name="phiOfN"></param>
        /// <returns></returns>
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

        public static (BigInteger p, BigInteger q) DixonRandomSquareAlgorithm(BigInteger N, BigInteger x, BigInteger y)
        {
            Console.WriteLine("Dixon Random Square Algorithm Start");
            BigInteger p = 0, q = 0;
            // find 2 numbers x, y such as
            // 1. x != (+/- y) mod N
            // 2. x^2 = (y^2) mod N
            var xSq = SquareAndMultiply(x, 2, N);
            var ySq = SquareAndMultiply(y, 2, N);
            var xModN = x % N;
            var yModN = y % N;
            
            if (xSq == ySq && xModN != yModN)
            {
                Console.WriteLine($@"{x} and {y} respect Dixon's random square axiom because their modular squares are equal: {x}^2 mod {N} = {xSq} and {y}^2 mod {N} = {ySq}
                                                                                            and {x} mod {N} != {y} mod {N}");
                var factor1 = x - 2;
                var factor2 = x + 2;

                var potentialFactor = EuclideanAlgorithm(factor2, N).gcd;
                var otherFactor = N / potentialFactor;

                if (potentialFactor % 1 != 0 && potentialFactor != 1 && otherFactor % 1 != 0 && otherFactor != 1)
                {
                    potentialFactor = EuclideanAlgorithm(factor1, N).gcd;
                    otherFactor = N / potentialFactor;
                }

                p = otherFactor;
                q = potentialFactor;
                Console.WriteLine($"{N} can be factored into {p} and {q}");
            }
            else
            {
                Console.WriteLine($"{x} and {y} do not respect Dixon's random square axiom");
            }

            Console.WriteLine("Dixon Random Square Algorithm End");
            return (p, q);
        }
    }
}
