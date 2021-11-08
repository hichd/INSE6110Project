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
                    #region CRT
                    //CRT2();
                    //CRT3();
                    #endregion

                    #region D-H
                    //DiffieHellmanKeyAgreement();
                    //DiffieHellmanKeyAgreement_ManInTheMiddleAttack();
                    //DiffieHellmanThreePassEncryption();
                    //#endregion

                    //#region RSA
                    //RsaExample();
                    //RsaDecryptionExample();
                    //RsaWithCrtToSpeedUpDecryption();
                    //RsaKnowPhiOfNAttack();
                    //RsaTwinPrimesAttack();
                    RsaCommonPAttack();
                    //RsaLowExponentAttack();
                    //RsaCommonModulusAttack();
                    //RsaChosenCipherTextAttack1Query();
                    //RsaChosenCipherTextAttack2Query();
                    //RsaDixonRandomSquareAlgorithm();
                    #endregion

                    //Utility.ProjectSetup();
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

        #region CRT
        private static void CRT2()
        {
            BigInteger a1 = 5, n1 = 11;
            BigInteger a2 = 3, n2 = 7;
            CryptoUtility.ChineeseRemainderTheorem2(a1, n1, a2, n2);
            Utility.PressAnyKeyToContinue();
        }

        private static void CRT3()
        {
            BigInteger a1 = 5, n1 = 7;
            BigInteger a2 = 3, n2 = 11;
            BigInteger a3 = 10, n3 = 13;
            CryptoUtility.ChineeseRemainderTheorem3(a1, n1, a2, n2, a3, n3);
            Utility.PressAnyKeyToContinue();
        }
        #endregion

        #region D-H
        private static void DiffieHellmanKeyAgreement()
        {
            var p = 101;
            var g = 17;

            var a = 19;
            var b = 13;

            var dH = new DiffieHellman(p, g);
            dH.KeyExchange(a, b);
            Utility.PressAnyKeyToContinue();
        }

        private static void DiffieHellmanKeyAgreement_ManInTheMiddleAttack()
        {
            var p = 101;
            var g = 17;

            var a = 19;
            var b = 13;

            var aEve = 11;
            var bEve = 29;

            var dH = new DiffieHellman(p, g);
            dH.KeyExchange_ManInTheMiddleAttack(a, b, aEve, bEve);
            Utility.PressAnyKeyToContinue();
        }

        private static void DiffieHellmanThreePassEncryption()
        {
            var p = 101;

            var a1 = 19;
            var a2 = 13;
            var m = 5;

            var dH = new DiffieHellman(p);
            dH.Encryption(a1, a2, m);

            Utility.PressAnyKeyToContinue();
        }
        #endregion

        #region RSA
        private static void RsaExample()
        {
            BigInteger p = 19, q = 29, e = 5, m = 11;

            var rsa = new Rsa(p, q, e);
            var c = rsa.Encrypt(m);
            rsa.Decrypt(c);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaDecryptionExample()
        {// Problem 3
            BigInteger p = 7, q = 11, e = 13, c = 17;

            var rsa = new Rsa(p, q, e);
            rsa.Decrypt(c);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaWithCrtToSpeedUpDecryption()
        {
            BigInteger p = 13, q = 17, e = 5, m = 4;

            var rsa = new Rsa(p, q, e);
            var c = rsa.Encrypt(m);
            rsa.DecryptWithCrt(c);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaKnowPhiOfNAttack()
        {
            var phiOfN = 192;
            var N = 221;

            var rsa = new Rsa();
            rsa.KnownPhiOfNAttack(phiOfN, N);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaTwinPrimesAttack()
        {// prob 6
            var e = 8743;
            var c = 99;

            var rsa = new Rsa();
            rsa.TwinPrimesAttack(11663);
            // after recovering private keys, decrypt cipher
            rsa.Init(rsa.P, rsa.Q, e);
            rsa.Decrypt(c);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaCommonPAttack()
        {// problem 4
            BigInteger n1 = 22577, n2 = 16157;
            var rsa = new Rsa();
            rsa.CommonPAttack(n1, n2);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaLowExponentAttack()
        {// prob 7
            BigInteger c1 = 128, n1 = 319;
            BigInteger c2 = 34, n2 = 697;
            BigInteger c3 = 589, n3 = 1081;

            var rsa = new Rsa();
            rsa.LowExponentAttack3(c1, n1, c2, n2, c3, n3);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaCommonModulusAttack()
        {// Problem 5
            BigInteger e1 = 7, c1 = 42, e2 = 17, c2 = 9, commonModulus = 143;
            var rsa = new Rsa();
            rsa.CommonModulusAttack(e1, c1, e2, c2, commonModulus);

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaChosenCipherTextAttack1Query()
        {// side effect of RSA multiplicative property
            // 1. get c from oracle and try to decrypt it
            var mOriginal = 40;
            var oracle = new Rsa();
            oracle.Init();
            var c = oracle.Encrypt(mOriginal);

            // 2. pick random message X {1, ..., N} and encrypt it with oracle public keys
            var rnd = new Random();
            var X = rnd.Next(1, 99999);
            var X_enc = oracle.Encrypt(X);

            // 2. prepare encrypted message for oracle to decrypt c1 = c * X^e mod N
            var c1 = c * X_enc % oracle.N;

            // 3. send c1 cipher text to oracle to decrypt
            var mX = oracle.Decrypt(c1);

            // 4. attacker can now retreive message
            var xInv = CryptoUtility.ModInverse(X, oracle.N);
            var m = mX * xInv % oracle.N;

            Console.WriteLine($@"
    1 Query - Chosen cipher text attack begin with m = {mOriginal}
            Attacker                                             Oracle with public key ({oracle._e}, {oracle.N})
                   <-------------------- sends c --------------------------
        pick X at random: X = {X}
        encrypt it X^e mod N = {X}^{oracle._e} mod {oracle.N} = {X_enc}

        take c1 = c * X^e mod N = {c} * {X}^{oracle._e} mod {oracle.N} = {c1}
        send to decryption oracle
                    -------------------------------------------------------->
                                                                    (c1)^d mod N = ({c1}^{oracle._d} mod {oracle.N} = m * X mod N = {mX}
                   <-------------------- sends m1 = {mX} ---------------------
        Attacker can now retrieve original message:
        m = m * X * X^-1 mod = = {mX} * {X}^-1 mod {oracle.N} = {mX} * {xInv} mod {oracle.N} = {mX * xInv} mod {oracle.N} = {m}
            ");

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaChosenCipherTextAttack2Query()
        {// side effect of RSA multiplicative property
            // 1. get c from oracle and try to decrypt it
            var mOriginal = 40;
            var oracle = new Rsa();
            oracle.Init();
            var c = oracle.Encrypt(mOriginal);

            // 2. factor c = c1 * c2
            var rnd = new Random();
            var c1 = rnd.Next(1, 99999);
            BigInteger c2 = 1;
            BigInteger gcd = 2;
            BigInteger invC1 = 1;
            while (gcd != 1)
            {
                gcd = CryptoUtility.EuclideanAlgorithm(c1, oracle.N).gcd;
                invC1 = CryptoUtility.ModInverse(c1, oracle.N, gcd == 1);
                c2 = c * invC1 % oracle.N;
            }

            // 3. send c1, c2 to oracle to decrypt and return corresponding m1, m2
            var m1 = oracle.Decrypt(c1);
            var m2 = oracle.Decrypt(c2);

            var m = m1 * m2 % oracle.N;

            Console.WriteLine($@"
    2 Queries - Chosen cipher text attack begin with m = {mOriginal}
            Attacker                                             Oracle with public key ({oracle._e}, {oracle.N})
                   <-------------------- sends c --------------------------
        pick c1 at random: c1 = {c1} such as gcd(c1, N) = gcd({c1}, {oracle.N}) = 1
        pick c2 = c * c1^(-1) mod N = {c} * {c1}^-1 mod {oracle.N} = {c} * {invC1} = {c2}

        send to decryption oracle
                    -------------------------------------------------------->
                                                                    (c1)^d mod N = ({c1}^{oracle._d} mod {oracle.N} = {m1}
                   <-------------------- sends m1 = {m1} ---------------------

        send to decryption oracle
                    -------------------------------------------------------->
                                                                    (c2)^d mod N = ({c2}^{oracle._d} mod {oracle.N} = {m2}
                   <-------------------- sends m2 = {m2} ---------------------

        Attacker can now retrieve original message:
        m = m1 * m2 mod N = = {m1} * {m2} mod {oracle.N} = {m1 * m2} mod {oracle.N} = {m}
            ");

            Utility.PressAnyKeyToContinue();
        }

        private static void RsaDixonRandomSquareAlgorithm()
        {
            BigInteger n = 77, x = 68, y = 2;
            CryptoUtility.DixonRandomSquareAlgorithm(n, x, y);

            Utility.PressAnyKeyToContinue();
        }
        #endregion
    }
}
