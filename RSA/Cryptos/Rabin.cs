using RSA.Cryptos.utils;
using System;
using System.Numerics;
using utils;

namespace RSA.Cryptos
{
    class Rabin
    {
        public BigInteger N { get; set; }
        public BigInteger P { get; set; }
        public BigInteger Q { get; set; }

        public Rabin(BigInteger p, BigInteger q)
        {
            P = p;
            Q = q;
            N = P * Q;
        }

        public BigInteger Encrypt(BigInteger m)
        {
            Utility.ShowSteps($@"
            Rabin ecnrypt message m = {m} with P = {P}, Q = {Q}, N = P * Q = {P} * {Q} = {N}
            P and Q need to satisfy conditions :
            P mod 4 = {P} mod 4 = {P % 4} = 3 => {P % 4 == 3}
            Q mod 4 = {Q} mod 4 = {Q % 4} = 3 => {Q % 4 == 3}
            
            C = m ^ 2 mod N = {m} ^ 2 mod {N} = {m * m} mod {N} = {(m * m) % N}
            ", true);

            return (m * m) % N;
        }

        public BigInteger Decrypt(BigInteger c)
        {
            var c_p = c % P;
            var c_q = c % Q;
            var exp_p = ((P + 1) / 4);
            var exp_q = ((Q + 1) / 4);
            var m_exp_p = (BigInteger)Math.Pow((double)c_p, (double)exp_p);
            var m_exp_q = (BigInteger)Math.Pow((double)c_q, (double)exp_q);
            var m_p_plus = m_exp_p % P;
            var m_p_minus = -m_exp_p % P;
            var m_q_plus = m_exp_q % Q;
            var m_q_minus = -m_exp_q % Q;

            Utility.ShowSteps("CRT with 2 equations needed for computing m with m_p+ and m_q+", true);
            var m = CryptoUtility.ChineeseRemainderTheorem2(m_exp_p, P, m_exp_q, Q);

            Utility.ShowSteps($@"
            m_p = ± c ^ [(P + 1)/4] mod P = ± {c} ^ [({P} + 1)/4] mod {P} = ± {c} ^ {(P + 1) / 4} mod {P} = ± {c_p} ^ {((P + 1) / 4)} mod {P} = ± {m_exp_p} mod {P} = ± { m_exp_p % P}
            m_q = ± c ^ [(Q + 1)/4] mod Q = ± {c} ^ [({Q} + 1)/4] mod {Q} = ± {c} ^ {(Q + 1) / 4} mod {Q} = ± {c_q} ^ {((Q + 1) / 4)} mod {Q} = ± {m_exp_q} mod {Q} = ± { m_exp_q % Q}
            
            solve using CRT 4 times
            
            m_p+ = {m_p_plus}
            m_p- = {m_p_minus}
            m_q+ = {m_q_plus}
            m_q- = {m_q_minus}

            m = {m}
            ", true);

            return m;
        }
    }
}
