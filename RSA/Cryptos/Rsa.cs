using RSA.Cryptos.utils;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace Cryptos
{
    public class Rsa
    {
        private const bool ShowSteps = false;

        #region private paramters
        private BigInteger P { get; set; }
        private BigInteger Q { get; set; }
        private BigInteger PhiOfN { get; set; }
        private BigInteger _d { get; set; }
        #endregion

        #region public parameters
        private BigInteger N { get; set; }
        private BigInteger _e { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// parameterless constructor, picks 2 large 16 bit non twin primes and exponents
        /// </summary>
        public Rsa()
        {
            Init();
        }

        /// <summary>
        /// RSA constructor with parameters for both private primes and public and private exponents
        /// </summary>
        /// <param name="p">private prime 1</param>
        /// <param name="q">private prime 2</param>
        /// <param name="e">public exponent</param>
        /// <param name="d">private exponent</param>
        public Rsa(BigInteger p, BigInteger q, BigInteger e, BigInteger d)
        {
            Init(p, q, e, d);
        }

        /// <summary>
        /// RSA constructor for partner public key with parameters for exponent and N
        /// </summary>
        /// <param name="n">public key parameter N</param>
        /// <param name="e">public exponent</param>
        public Rsa(BigInteger e, BigInteger n)
        {
            Init(new BigInteger(), new BigInteger(), e, new BigInteger(), n);
        }
        #endregion

        #region Init
        /// <summary>
        /// Initial parameter setup for RSA
        /// </summary>
        /// <param name="p">private key parameter large prime 1</param>
        /// <param name="q">private key parameter large prime 2</param>
        /// <param name="e">public key exponent</param>
        /// <param name="d">private key exponent</param>
        /// <param name="n">public key parameter</param>
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
        #endregion

        #region Encryption

        /// <summary>
        /// Takes string message and encrypts it using instance public key paramters
        /// </summary>
        /// <param name="m">plaintext message</param>
        /// <returns>integer representation of the encrypted message</returns>
        public List<BigInteger> Encrypt(string m)
        {
            return Encrypt(m, _e, N, ShowSteps);
        }

        /// <summary>
        /// Takes string message and public key
        /// </summary>
        /// <param name="m">plaintext message</param>
        /// <param name="e">public exponent</param>
        /// <param name="n">public key parameter</param>
        /// <param name="showSteps"></param>
        /// <returns>integer representation of the encrypted message</returns>
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

        /// <summary>
        /// Takes integer cipher and encrypts it using instance public key paramters
        /// </summary>
        /// <param name="m">integer representation of plaintext message</param>
        /// <returns>integer representation of the encrypted message</returns>
        public BigInteger Encrypt(BigInteger m)
        {
            return Encrypt(m, _e, N);
        }

        /// <summary>
        /// Takes integer cipher and encrypts it using passed in public key paramters
        /// </summary>
        /// <param name="m">integer representation of plaintext message</param>
        /// <param name="e">provided public exponent</param>
        /// <param name="n">provided public key parameter N</param>
        /// <returns>integer representation of the encrypted message using provided public key</returns>
        public BigInteger Encrypt(BigInteger m, BigInteger e, BigInteger n)
        {
            Utility.ShowSteps("******************************************************************************************************", true);
            Utility.ShowSteps($"BEGIN RSA ENCRYPTION FOR MESSAGE m = {m}", true);

            var result = CryptoUtility.SquareAndMultiply(m, e, n, true);

            Utility.ShowSteps($"ENCRYPTION ENDED WITH c = {result} :", true);
            Utility.ShowSteps("/////////////////////////////////////////////////////////////////////////////////////////////////////////", true);

            return result;
        }
        #endregion

        #region Decryption
        /// <summary>
        /// Decrypts list of integer ciphers into a string message using instance private key parameters
        /// </summary>
        /// <param name="cipherList">integer cipher list</param>
        /// <returns>integer representation of the encrypted message</returns>
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
        /// Decrypts single integer cipher into a string message using provided private and public key parameters
        /// </summary>
        /// <param name="c">integer cipher</param>
        /// <param name="d">provided private exponent</param>
        /// <param name="n">provided public key element N</param>
        /// <returns>integer representation of the decypted integer message</returns>
        public BigInteger Decrypt(BigInteger c, BigInteger d, BigInteger n)
        {
            Utility.ShowSteps("******************************************************************************************************", true);
            Utility.ShowSteps($"BEGIN RSA DECRYPTION FOR CIPHER c = {c}", true);

            var result = CryptoUtility.SquareAndMultiply(c, d, n, true);

            Utility.ShowSteps($"DECRYPTION ENDED WITH m = {result} :", true);
            Utility.ShowSteps("/////////////////////////////////////////////////////////////////////////////////////////////////////////", true);

            return result;
        }

        /// <summary>
        /// Decrypts single integer cipher into a string message using instance key parameters
        /// </summary>
        /// <param name="c">integer cipher</param>
        /// <returns>integer representation of the decypted integer message</returns>
        public BigInteger Decrypt(BigInteger c)
        {
            return Decrypt(c, _d, N);
        }
        #endregion
    }
}
