using RSA.Cryptos.utils;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace Cryptos
{
    public class Rsa
    {
        private const bool ShowSteps = false;

        //private paramters
        private BigInteger P { get; set; }
        private BigInteger Q { get; set; }
        private BigInteger PhiOfN { get; set; }
        private BigInteger _d { get; set; }

        //public parameters
        private BigInteger N { get; set; }
        private BigInteger _e { get; set; }

        /// <summary>
        /// parameterless constructor, picks 2 large 16 bit non twin primes and exponent
        /// </summary>
        public Rsa()
        {
            Init();
        }

        /// <summary>
        /// Initial parameter setup for RSA
        /// </summary>
        /// <param name="p">private large prime 1</param>
        /// <param name="q">private large prime 2</param>
        /// <param name="e">public exponent</param>
        private void Init(BigInteger? p = null, BigInteger? q = null, BigInteger? e = null, BigInteger? d = null, BigInteger? n = null)
        {
            if (!n.HasValue)
            {
                P = p ?? Utility.Generate16BitPrime();
                Q = q ?? Utility.Generate16BitPrime(P);
                Utility.ShowSteps($"1. Select two prime numbers: P = {P}, Q = {Q}", ShowSteps);

                N = P * Q;
                Utility.ShowSteps($"2. Compute N = P * Q = {P} * {Q} = {N}", ShowSteps);

                PhiOfN = CryptoUtility.RsaPhiFunction(P, Q);
                Utility.ShowSteps($"3. Compute Phi(N) = (P - 1) * (Q - 1)  = ({P} - 1) * ({Q} - 1) = {PhiOfN}", ShowSteps);

                _e = e ?? PhiOfN.GenerateRsaPublicExponent();
                Utility.ShowSteps($"4. Select a public-key e = {_e}", ShowSteps);

                _d = d ?? _e.ModInverse(PhiOfN, ShowSteps);
                Utility.ShowSteps($"5. Find the corresponding private-key d = {_d}", ShowSteps);

                Utility.ShowSteps($"6. Publish your public-key(N, e) = ({N}, {_e})", ShowSteps);
            }
            else
            {
                N = n.Value;
                _e = e.Value;
                Utility.ShowSteps($"RSA public key: N = {N}, e = {e}", ShowSteps);
            }
        }

        public List<BigInteger> Encrypt(string m, BigInteger e, BigInteger n, bool showSteps = true)
        {
            Utility.ShowSteps("******************************************************************************************************", showSteps);
            Utility.ShowSteps($"BEGIN RSA ENCRYPTION FOR MESSAGE m = {m}", showSteps);

            var cipherText = new List<BigInteger>();
            var mBigIntegerList = m.StringToBigInteger();

            int i = 0;
            mBigIntegerList.ForEach(x =>
            {
                Utility.ShowSteps($"m{++i}_int = {x}", showSteps);
                cipherText.Add(CryptoUtility.SquareAndMultiply(x, e, n, showSteps));
            });

            Utility.ShowSteps("Encryption Ended with cipher list :", ShowSteps);
            i = 0;
            cipherText.ForEach(x => Utility.ShowSteps($"c{++i}_int = {x}", showSteps));
            Utility.ShowSteps("/////////////////////////////////////////////////////////////////////////////////////////////////////////", ShowSteps);

            return cipherText;
        }

        public List<BigInteger> Encrypt(string m)
        {
            return Encrypt(m, _e, N, ShowSteps);
        }

        public string Decrypt(List<BigInteger> cipherList)
        {
            Utility.ShowSteps("******************************************************************************************************", ShowSteps);
            Utility.ShowSteps($"BEGIN RSA DECRYPTION FOR CIPER LIST :", ShowSteps);
            int i = 0;
            cipherList.ForEach(x => Utility.ShowSteps($"c_{++i} = {x}", ShowSteps));

            var bigIntegerList = new List<BigInteger>();

            cipherList.ForEach(x =>
            {
                bigIntegerList.Add(CryptoUtility.SquareAndMultiply(x, _d, N, ShowSteps));
            });

            Utility.ShowSteps("Decryption Ended with message list :", ShowSteps);
            i = 0;
            bigIntegerList.ForEach(x => Utility.ShowSteps($"c_{++i} = {x}", ShowSteps));

            var message = bigIntegerList.BigIntegerToString();
            Utility.ShowSteps($"DECRYPTION RESULT: Message = {message}", ShowSteps);
            Utility.ShowSteps("/////////////////////////////////////////////////////////////////////////////////////////////////////////", ShowSteps);

            return message;
        }

        /// <summary>
        /// RSA constructor with parameters for both primes and exponent
        /// </summary>
        /// <param name="p">private prime 1</param>
        /// <param name="q">private prime 2</param>
        /// <param name="e">public exponent</param>
        public Rsa(BigInteger p, BigInteger q, BigInteger e, BigInteger d)
        {
            Init(p, q, e, d);
        }

        /// <summary>
        /// RSA constructor for partner public key with parameters for exponent and N
        /// </summary>
        /// <param name="n">public N</param>
        /// <param name="e">public exponent</param>
        public Rsa(BigInteger e, BigInteger n)
        {
            Init(new BigInteger(), new BigInteger(), e, new BigInteger(), n);
        }

        public BigInteger Encrypt(BigInteger m)
        {
            return Encrypt(m, _e, N);
        }

        public BigInteger Encrypt(BigInteger m, BigInteger e, BigInteger n)
        {
            Utility.ShowSteps("******************************************************************************************************", true);
            Utility.ShowSteps($"BEGIN RSA ENCRYPTION FOR MESSAGE m = {m}", true);

            var result = CryptoUtility.SquareAndMultiply(m, e, n, true);

            Utility.ShowSteps($"ENCRYPTION ENDED WITH c = {result} :", true);
            Utility.ShowSteps("/////////////////////////////////////////////////////////////////////////////////////////////////////////", true);

            return result;
        }

        public BigInteger Decrypt(BigInteger c, BigInteger d, BigInteger n)
        {
            Utility.ShowSteps("******************************************************************************************************", true);
            Utility.ShowSteps($"BEGIN RSA DECRYPTION FOR CIPHER c = {c}", true);

            var result = CryptoUtility.SquareAndMultiply(c, d, n, true);

            Utility.ShowSteps($"DECRYPTION ENDED WITH m = {result} :", true);
            Utility.ShowSteps("/////////////////////////////////////////////////////////////////////////////////////////////////////////", true);

            return result;
        }

        public BigInteger Decrypt(BigInteger c)
        {
            return Decrypt(c, _d, N);
        }
    }
}
