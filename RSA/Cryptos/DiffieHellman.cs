using RSA.Cryptos.utils;
using System;
using System.Numerics;

namespace RSA.Cryptos
{
    public class DiffieHellman
    {
        #region Public key parameters
        public BigInteger P;
        public BigInteger _g;
        #endregion

        // Alice
        public BigInteger _a1;
        public BigInteger _a2;
        public BigInteger aCipher;
        public BigInteger aKey;
        // Bob
        public BigInteger _b1;
        public BigInteger _b2;
        public BigInteger bCipher;
        public BigInteger bKey;
        // Ever: attacker
        public BigInteger _a1Eve;
        public BigInteger _b1Eve;
        public BigInteger aEveCipher;
        public BigInteger bEveCipher;

        public DiffieHellman(BigInteger p, BigInteger g)
        {
            Init(p, g);
        }
        public DiffieHellman(BigInteger p)
        {
            Init(p);
        }

        public void Init(BigInteger p, BigInteger? g = null)
        {
            Console.WriteLine(g.HasValue 
                ? "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Diffie-Hellman key agreement\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
                : "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Diffie-Hellman 3-pass encryption\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\");
            P = p;
            Console.WriteLine($"Large prime P = {P}");
            if(g.HasValue)
            {
                _g = g.Value;
                Console.WriteLine($"random generator g = {_g} such that g in [1, ..., {P-1}]");
            }
        }

        public void KeyExchange(BigInteger a, BigInteger b)
        {
            _a1 = a;
            _b1 = b;
            aCipher = CryptoUtility.SquareAndMultiply(_g, _a1, P);
            bCipher = CryptoUtility.SquareAndMultiply(_g, _b1, P);
            aKey = CryptoUtility.SquareAndMultiply(bCipher, _a1, P);
            bKey = CryptoUtility.SquareAndMultiply(aCipher, _b1, P);
            Console.WriteLine($"***************************************************************************************************");
            Console.WriteLine($"                     Alice                                                   Bob");
            Console.WriteLine($@"              Alice chooses a = {_a1}                                   Bob chooses b = {_b1}
              such that ({_g}^{_a1})                                      such that ({_g}^{_b1}) 
              and 0 <= a <= P - 2                                   and 0 <= b <= P - 2
              0 <= {_a1} <= {P - 2}                                         0 <= {_b1} <= {P - 2}");
            Console.WriteLine($"                 ------ Alice sends cipher = ({_g}^{_a1}) mod {P} = {aCipher} to Bob ------->");
            Console.WriteLine($"                 <----- Bob sends cipher = ({_g}^{_b1}) mod {P} = {bCipher} to Alice -------");
            Console.WriteLine($@"              Alice solves key = ({bCipher}^{_a1}) mod {P}                    Bob solves key = ({aCipher}^{_b1}) mod {P}");
            Console.WriteLine($"***************************************************************************************************");
            Console.WriteLine($@"Alice key = {aKey}");
            Console.WriteLine($@"Bob key = {bKey}");
            Console.WriteLine($@"key is the same : {bKey==aKey}");
        }

        public void KeyExchange_ManInTheMiddleAttack(BigInteger a, BigInteger b, BigInteger aEve, BigInteger bEve)
        {
            _a1 = a;
            _b1 = b;
            _a1Eve = aEve;
            _b1Eve = bEve;
            aCipher = CryptoUtility.SquareAndMultiply(_g, _a1, P);
            aEveCipher = CryptoUtility.SquareAndMultiply(_g, _a1Eve, P);
            bCipher = CryptoUtility.SquareAndMultiply(_g, _b1, P);
            bEveCipher = CryptoUtility.SquareAndMultiply(_g, _b1Eve, P);
            aKey = CryptoUtility.SquareAndMultiply(bEveCipher, _a1, P);
            var aEveKey = CryptoUtility.SquareAndMultiply(aCipher, _b1Eve, P);
            var bEveKey = CryptoUtility.SquareAndMultiply(bCipher, _a1Eve, P);
            bKey = CryptoUtility.SquareAndMultiply(aEveCipher, _b1, P);
            Console.WriteLine($"**************************************** Diffie-Hellman key exchange man in the middle attack ***********************************");
            Console.WriteLine($"                Alice                                                                                     Bob");
            Console.WriteLine($@"        Alice chooses a = {_a1}                                                                      Bob chooses b = {_b1}
        such that ({_g}^{_a1})                                                                          such that ({_g}^{_b1}) 
        and 0 <= a <= P - 2                                                                         and 0 <= b <= P - 2
        0 <= {_a1} <= {P - 2}                                                                               0 <= {_b1} <= {P - 2}");
            Console.WriteLine($"          ------ Alice sends cipher = ({_g}^{_a1}) mod {P} = {aCipher} to Bob ---->");
            Console.WriteLine($"                                               Eve intercepts, blocks and chooses a' = {_a1Eve}");
            Console.WriteLine($"                                               ----------- sends cipher = ({_g}^{_a1Eve}) mod {P} = {aEveCipher} to Bob ------->");
            Console.WriteLine($"                                                     <----- Bob sends cipher = ({_g}^{_b1}) mod {P} = {bCipher} to Alice ---");
            Console.WriteLine($"                                        Eve intercepts, bloacks and chooses b' = {_b1Eve}");
            Console.WriteLine($"          <----- Eve intercepts sends cipher = ({_g}^{_b1Eve}) mod {P} = {bEveCipher} to Alice -------");
            Console.WriteLine($@"       Alice solves key = ({bEveCipher}^{_a1}) mod {P} = {aKey}                                      Bob solves key = ({aEveCipher}^{_b1}) mod {P} = {bKey}");
            Console.WriteLine($"************************************************************************************************************************************");
            Console.WriteLine($@"Alice key = {aKey}, Eve's key for Alice = {aEveKey}, key is the same : {aKey == aEveKey}");
            Console.WriteLine($@"Bob key = {bKey}, Eve's key for Alice = {bEveKey}, key is the same : {bKey == bEveKey}");
        }

        public void Encryption(BigInteger a1, BigInteger b1, BigInteger m)
        {
            var pMinus1 = P - 1;
            _a1 = a1;
            _b1 = b1;
            var gcdA1 = CryptoUtility.EuclideanAlgorithm(_a1, pMinus1).gcd;
            var gcdB1 = CryptoUtility.EuclideanAlgorithm(_b1, pMinus1).gcd;
            _a2 = CryptoUtility.ModInverse(a1, pMinus1);
            _b2 = CryptoUtility.ModInverse(b1, pMinus1);
            var mA1 = CryptoUtility.SquareAndMultiply(m, _a1, P);
            var mB1 = CryptoUtility.SquareAndMultiply(mA1, _b1, P);
            var mA2 = CryptoUtility.SquareAndMultiply(mB1, _a2, P);
            var mB2 = CryptoUtility.SquareAndMultiply(mA2, _b2, P);
            Console.WriteLine($@"
    **************************** 3-Pass Diffie-Hellman Encryption for m = {m} ********************************
                    Alice                                                    Bob
              Alice chooses a2                                        Bob chooses b2
              such that a1*a2 mod (P - 1) = 1                         such that b1*b2 mod (P - 1) = 1
              a2 = (a1 ^ -1) mod (P - 1)                              b2 = (b1 ^ -1) mod (P - 1) 
              a2 = ({_a1}^-1) mod ({P} - 1)                               b2 = ({_b1}^-1) mod ({P} - 1)
              a2 = ({_a1}^-1) mod ({pMinus1})                                  b2 = ({_b1}^-1) mod ({pMinus1})
              and gcd(a1,P-1) = 1                                      and gcd(a1,P-1) = 1
                gcd({_a1},{pMinus1}) = {gcdA1}                                        gcd({b1},{pMinus1}) = {gcdB1}
                   a2 = {_a2}                                               b2 = {_b2}
                   ------ Alice sends m^a1 = ({m}^{_a1}) mod {P} = {mA1} to Bob ------->
                   <--- Bob sends (m^a1)^b1 = ({mA1}^{_b1}) mod {P} = {mB1} to Alice ----
                   ---- Alice sends ((m^a1)^b1)^a2 = ({m}^{mB1}) mod {P} = {mA2} to Bob ---->
                                                                    Bob solves m = (((m^a1)^b1)^a2)^b2 mod {P}
                                                                        m = ({mA2}^{_b2}) mod {P} = {mB2}
    ************************** 3-Pass Diffie-Hellman Encryption for m = {m} : {m == mB2} ***************************
");

        }
    }
}
