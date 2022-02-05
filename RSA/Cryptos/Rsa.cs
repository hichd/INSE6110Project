using RSA.Cryptos.utils;
using System;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace Cryptos
{
    /// <summary>
    /// RSA model, key setup implementation, encryption/decryption implementations
    /// </summary>
    public class Rsa
    {
        private const bool ShowSteps = false;

        #region private paramters
        public BigInteger P { get; set; }
        public BigInteger Q { get; set; }
        public BigInteger PhiOfN { get; set; }
        public BigInteger _d { get; set; }
        #endregion

        #region public parameters
        public BigInteger N { get; set; }
        public BigInteger _e { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// parameterless constructor, picks 2 large 16 bit non twin primes and exponents
        /// </summary>
        public Rsa(bool isInit = false)
        {
            if (isInit) Init();
        }

        /// <summary>
        /// RSA constructor with parameters for both private primes and public and private exponents
        /// </summary>
        /// <param name="p">private prime 1</param>
        /// <param name="q">private prime 2</param>
        /// <param name="e">public exponent</param>
        /// <param name="d">private exponent</param>
        public Rsa(BigInteger p, BigInteger q, BigInteger e, BigInteger? d = null)
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
        public void Init(BigInteger? p = null, BigInteger? q = null, BigInteger? e = null, BigInteger? d = null, BigInteger? n = null)
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

        public BigInteger DecryptWithCrt(BigInteger c)
        {
            Console.WriteLine("***************************** RSA Decryption with CRT ***************************");
            Console.WriteLine($@"
    since N = P * Q
    divide m into m_p and m_q such that m = m_p mod P * m_q mod Q = ? mod (P * Q)

    m_p = ({c}^{_d}) mod {P} = ({c} mod {P})^({_d} mod ({P} - 1)) mod {P} = ({c % P}^{_d % (P - 1)}) mod {P}
    m_q = ({c}^{_d}) mod {Q} = ({c} mod {Q})^({_d} mod ({Q} - 1)) mod {Q} = ({c % Q}^{_d % (Q - 1)}) mod {Q}

    solve m_p and m_q with square and multiply 

            ");

            var m_p = CryptoUtility.SquareAndMultiply(c % P, _d % (P - 1), N) % P;
            var m_q = CryptoUtility.SquareAndMultiply(c % Q, _d % (Q - 1), N) % Q;

            Console.WriteLine($@"

    m_p = ({c % P}^{_d % (P - 1)}) mod {P} = {m_p} mod {P}
    m_q = ({c % Q}^{_d % (Q - 1)}) mod {Q} = {m_q} mod {Q}

    now we can use CRT to solve
            ");

            var message = CryptoUtility.ChineeseRemainderTheorem2(m_p, P, m_q, Q);
            Console.WriteLine($"***************** RSA CRT decryption ended, if both CRT checks true then message = {message}");
            return message;
        }
        #endregion

        #region Attacks
        public void KnownPhiOfNAttack(BigInteger phiOfN, BigInteger N)
        {
            var a = 1; 
            var b = -(N + 1 - phiOfN);
            var c = N;
            var insideSqrt = (b * b) - (4 * a * c);
            var sqrt = Math.Sqrt((double)insideSqrt);
            var minResult = (-b - (BigInteger)sqrt) / 2;
            var maxResult = (-b + (BigInteger)sqrt) / 2;

            P = minResult < 0 ? maxResult : minResult;
            Console.WriteLine($@"
        Known phi(N) attack: if phi(N) is known, we can factorize it to know P and Q
            hi(N) = (P - 1) * (Q - 1) = (P - 1) * (N/P - 1)
            {phiOfN} = (P - 1) * (Q - 1) = (P - 1) * (N/P - 1) = (P - 1) * (Q - 1) = (P - 1) * ({N}/P - 1)
            1 * P^2 - (N + 1 - phi(N))P + N = 0
            1 * P^2 - ({N} + 1 - {phiOfN}) * P + {N} = 0
            a = 1
            b = - ({N} + 1 - {phiOfN}) = {b}
            c = {N}
            P = (-b ± sqrt[b^2 - 4 * a * c])/(2 * a) = (-{b} ± sqrt[{b*b} - 4 * {a*c}])/2 = ({-b} ± sqrt[{insideSqrt}])/2 = ({-b} ± {sqrt})/2
            P = {minResult} or P = {maxResult}, do not pick negative result

            Q = N / P;
            P = {P} and Q = {Q}, N = P * Q = {P} * {Q} = {P*Q} = {N}
        END OF KNOW PHI OF N ATTACK");
        }

        public void TwinPrimesAttack(BigInteger n)
        {
            N = n;
            var a = 1;
            var b = 2;
            var c = -N;
            var insideSqrt = (b * b) - (4 * a * c);
            var sqrt = Math.Sqrt((double)insideSqrt);
            var maxResult = (-b + (BigInteger)sqrt) / 2;
            P = maxResult;
            Q = N / P;

            Console.WriteLine($@"
        Twin primes attack: N = {N} = P * Q = P * (P - 2)
            0 = P^2 + 2 * P - N
            0 = P^2 + 2 * P - {N}
            a = {a}
            b = {b}
            c = {c}
            P = (- b + sqrt[b^2 - 4 * a * c])/(2 * a) = ({-b} + sqrt[{insideSqrt}])/2 = ({-b} + {sqrt})/2  = {maxResult}
            disregard negative part of factorization
        Twin primes attack: N = {N} = {P} * {Q} = {P} * ({P} - 2) = {P * Q}; Q = N / P = {N} / {P} = {Q}");
        }

        public void CommonPAttack(BigInteger n1, BigInteger n2)
        {
            var n = (BigInteger)Math.Max((double)n1, (double)n2);
            var a = (BigInteger)Math.Min((double)n1, (double)n2);
            var p = CryptoUtility.EuclideanAlgorithm(a, n).gcd;

            Console.WriteLine($@"
        Common P Attack Start
            N1 = P * Q1
            {n1} = P * Q1

            N2 = P * Q2
            {n2} = P * Q2

            same P for multiple communications
            P = gcd(N1, N2) = gcd({n1}, {n2}) = {p}

            total break
            Q1 = N1 / P
            Q1 = {n1} / {p} = {(double)n1/(double)p}

            Q2 = N2 / P
            Q2 = {n2} / {p} = {(double)n2 / (double)p}
        Common P Attack End
        ");
        }

        public void LowExponentAttack3(BigInteger c1, BigInteger n1, BigInteger c2, BigInteger n2, BigInteger c3, BigInteger n3)
        {
            _e = 3;

            Console.WriteLine($@"
        Low exponent attack, e = 3
            
            X = c1 mod N1 = {c1} mod {n1}
            X = c2 mod N2 = {c2} mod {n2}
            X = c3 mod N3 = {c3} mod {n3}
            ");

            var mCube = CryptoUtility.ChineeseRemainderTheorem3(c1, n1, c2, n2, c3, n3);
            var m = Math.Pow((double)mCube, 1.0 / 3.0);

            Console.WriteLine($@"
            m^3 = {mCube} => (m^3)^(1/3) = m = {m}
        Low exponent attack e = {_e}, m = {m} END ****************");
        }

        public void LowExponentAttack2(BigInteger c1, BigInteger n1, BigInteger c2, BigInteger n2)
        {
            _e = 3;

            Console.WriteLine($@"
        Low exponent attack, e = 3
            
            X = c1 mod N1 = {c1} mod {n1}
            X = c2 mod N2 = {c2} mod {n2}
            ");

            var mSq = CryptoUtility.ChineeseRemainderTheorem2(c1, n1, c2, n2);
            var m = Math.Pow((double)mSq, 1.0 / 2.0);

            Console.WriteLine($@"
            m^2 = {mSq} => (m^2)^(1/2) = m = {m}
        Low exponent attack e = {_e}, m = {m} END ****************");
        }

        public void CommonModulusAttack(BigInteger e1, BigInteger c1, BigInteger e2, BigInteger c2, BigInteger commonModulus)
        {
            N = commonModulus;

            if (e1 > e2)
            {
                var eTemp = e2;
                e2 = e1;
                e1 = eTemp;
            }

            var gcd = CryptoUtility.EuclideanAlgorithm(e1, e2).gcd;
            var a = CryptoUtility.ModInverse(e1, e2);
            var b = (1 - (a * e1)) / e2;
            Console.WriteLine("************** Common Modulus Attack Start");
            BigInteger c1PowA = 1;
            if (a < 0)
            {
                Console.WriteLine($";;;;;;;;; a = {a} is < 0, calculate inverse then square and multiply ;;;;;;;;;");
                var inverse = CryptoUtility.ModInverse(c1, N);
                a = -a;
                c1PowA = CryptoUtility.SquareAndMultiply(inverse, a, N);
                a = -a;
            }
            else
            {
                c1PowA = CryptoUtility.SquareAndMultiply(c1, a, N);

            }

            BigInteger c2PowB = 1;
            if (b < 0)
            {
                Console.WriteLine($";;;;;;;;; b = {b} is < 0, calculate inverse then square and multiply ;;;;;;;;;");
                var inverse = CryptoUtility.ModInverse(c2, N);
                b = -b;
                c2PowB = CryptoUtility.SquareAndMultiply(inverse, b, N);
                b = -b;
            }
            else
            {
                c2PowB = CryptoUtility.SquareAndMultiply(c2, b, N);

            }

            Console.WriteLine($@"
        Common Modulus Attack
            e1 = {e1}, c1 = {c1}
            e2 = {e2}, c2 = {c2}
            must satisfy condition
            a * e1 + b * e2 = 1 and gcd(e1, e2) = gcd({e1}, {e2}) = {gcd}
            then c1^a * c2^b mod N = m
            a = (e1^-1) mod e2 = ({e1}^-1) mod {e2} = {a}
            b = [1 - (a * e1)] / e2 = [1 - ({a} * {e1})] / {e1} = [1 - {a * e1}]/{e2} = {1 - (a * e1)} / {e2} = {b}
            m = c1^a * c2^b mod N = {c1}^{a} * {c2}^{b} mod {N} = {c1PowA} * {c2PowB} mod {N} = {c1PowA%N} * {c2PowB%N} mod {N} = {c1PowA % N * c2PowB % N} mod {N}
            m = {(c1PowA % N * c2PowB % N) % N}
        Common Modulus Attack End with m = {(c1PowA % N * c2PowB % N) % N}
        ");
        }
        #endregion
    }
}
