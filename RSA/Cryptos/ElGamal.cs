using RSA.Cryptos.utils;
using System;
using System.Numerics;
using utils;

namespace RSA.Cryptos
{
    public class ElGamal
    {
        public BigInteger P { get; set; }
        public BigInteger g { get; set; }
        public BigInteger X { get; set; } // {1, ... , P - 1}
        public BigInteger K { get; set; } // {1, ... , P - 1}
        public BigInteger r { get; set; }
        public BigInteger Y { get; set; }

        public ElGamal(BigInteger p, BigInteger g, BigInteger x)
        {
            P = p;
            X = x;
            this.g = g;
            Y = (BigInteger)Math.Pow((double)g, (double)X) % P;
            Utility.ShowSteps($@"
            El gamal - Key setup
            y = g ^ x mod P = {this.g} ^ {X} mod {P} = {Y}
            publish g = {g}, P = {P}, y = {Y}
            ", true);
        }

        public BigInteger Encrypt(BigInteger m, BigInteger k)
        {
            K = k;
            r = (BigInteger)Math.Pow((double)g, (double)K) % P;
            var c = m * ((BigInteger)Math.Pow((double)Y, (double)K)) % P;
            Utility.ShowSteps($@"
            Encryption
            r = {g} ^ {K} mod {P} = {r}
            c = m * y ^ k mod P = {m} * {Y} ^ {K} mod {P} = {m} * {(BigInteger)Math.Pow((double)Y, (double)K)} mod {P} = {m * (BigInteger)Math.Pow((double)Y, (double)K)} mod {P} = {m * (BigInteger)Math.Pow((double)Y, (double)K) % P}
            send r = {r} and c = {c}
            ", true);
            return c;
        }

        public BigInteger Decrypt(BigInteger c)
        {
            Utility.ShowSteps("mod inverse and square and multiply computations needed for encryption", true);
            var rModInv = CryptoUtility.ModInverse(r, P);
            var rModInvX = CryptoUtility.SquareAndMultiply(rModInv, X, P);
            BigInteger m = (c * rModInvX) % P;
            Utility.ShowSteps($@"
            Decryption
            m = c * r ^ -X mod P = {c} * {r} ^ -{X} mod {P} = {c} * {rModInvX} mod {P} = {c * rModInvX} mod {P} = {c} * {rModInvX} mod {P} = {m}

            to solve {r} ^ -{X} mod {P}
            first solve {r} ^ -1 mod {P} = {rModInv}
            then solve {rModInv} ^ {X} mod {P} = {rModInvX}
            ", true);
            return m;
        }
    }
}
