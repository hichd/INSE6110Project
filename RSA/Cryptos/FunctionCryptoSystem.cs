using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using utils;

namespace RSA.Cryptos
{
    public class FunctionCryptoSystem
    {
        public BigInteger P { get; set; }
        public BigInteger Q { get; set; }
        public BigInteger B { get; set; }
        public BigInteger N { get; set; }
        
        public FunctionCryptoSystem(BigInteger p, BigInteger q, BigInteger b)
        {
            B = b;
            P = p;
            Q = q;
            N = P * Q;
        }

        public BigInteger Encrypt(BigInteger m)
        {
            var c = ((BigInteger)Math.Pow((double)m, 2) + (m * B)) % N;
            Utility.ShowSteps($@"
            Encryption
            N = P * Q = {P} * {Q} = {N}
            c = (X^2 + XB) mod N = ({m}^2 + ({m} * {B})) mod {N} = {m} ({m} + {B}) mod {N} = {m} * {m+B} mod {N} = {m*(m+B)} mod {N} = {c}
            ", true);
            return c;
        }

        public void Decrypt(BigInteger m)
        {
            var a = m;
            var b = B;
            var c = -1;
            var insideSqrt = (b * b) - (4 * a * c);
            var sqrt = (BigInteger)Math.Sqrt((double)insideSqrt);
            var y = sqrt % N;
            var y_p = (BigInteger)Math.Pow((double)y, (double)(P + 1) / 4) % P;
            var y_q = (BigInteger)Math.Pow((double)y, (double)(Q + 1) / 4) % Q;

            Utility.ShowSteps($@"
            Decryption
            c = m (m + b)
            c = m^2+mb
            m^2 + bm - c = 0
            m^2 + {B}*m - c = 0;
            a = m
            b = {B}
            c = -1
            P = (- b + sqrt[b^2 - 4 * a * c])/(2 * a) = ({-B} + sqrt[{B}^2 - 4 * {m} * {-1} ])/(2*{m})

            y = sqrt [{B}^2 - 4 * {m} * {-1} ]) mod {N} = sqrt[{insideSqrt}] mod {N} = {sqrt} mod {N} = {y}
            if P, Q = 3 mod 4
            P mod 4 = {P} mod 4 = {P%4} => {P%4 == 3}
            Q mod 4 = {Q} mod 4 = {Q%4} => {Q%4 == 3}
            
            y_p = ± y ^ (P + 1)/4 mod P = ± {y} ^ ({P} + 1)/4 mod {P} = ± {y} ^ {(P + 1)/4} mod {P} = ± {(BigInteger)Math.Pow((double)y, (double)(P+1)/4)} mod {P} = ± {(BigInteger)Math.Pow((double)y, (double)(P + 1) / 4) % P}
            y_p = ± y ^ (P + 1)/4 mod P = ± {y} ^ ({Q} + 1)/4 mod {Q} = ± {y} ^ {(Q + 1)/4} mod {Q} = ± {(BigInteger)Math.Pow((double)y, (double)(Q+1)/4)} mod {Q} = ± {(BigInteger)Math.Pow((double)y, (double)(Q + 1) / 4) % Q}
            ", true);
        }
    }
}
