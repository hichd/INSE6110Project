using Cryptos;
using RSA.Cryptos.utils;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace Profiles
{
    public class MyDataProfile : BaseDataProfile
    {
        public readonly BigInteger P = new BigInteger(35759);
        public readonly BigInteger Q = new BigInteger(35879);
        public readonly BigInteger _d = new BigInteger(1093168051);
        public readonly BigInteger PhiOfN;

        public MyDataProfile()
        {
            PhiOfN = CryptoUtility.RsaPhiFunction(P, Q);
            N = new BigInteger(1282997161);
            _e = 311;
            ID = 27775237;
            Message = "RSA";
            Rsa = new Rsa(P, Q, _e, _d);
            MessageToSign = "Hicham Daou";
            DecryptAndSign();
        }

        public void DecryptAndSign()
        {
            // decrypt partner's cipher text
            CipherList = new List<BigInteger> { 970461482 };
            Cipher = $"[{string.Join(", ", CipherList)}]";
            Message = Rsa.Decrypt(CipherList);
            MessageChunks = $"['{string.Join("', '", Message.ChunksUpto(3))}']";

            // sign message to send to partner
            MessageToSignChunks = $"['{string.Join("', '", MessageToSign.ChunksUpto(3))}']";
            Signature = $"['{string.Join("', '", Rsa.Encrypt(MessageToSign, _d, N, false))}']";
        }
    }
}
