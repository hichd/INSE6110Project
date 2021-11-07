using Cryptos;
using System.Collections.Generic;
using System.Numerics;

namespace RSA.Profiles
{
    public class MyData
    {
        public readonly BigInteger P = new BigInteger(35759);
        public readonly BigInteger Q = new BigInteger(35879);
        public readonly BigInteger _d = new BigInteger(1093168051);
        public readonly BigInteger _e = 311;
        public readonly BigInteger N = new BigInteger(1282997161);
        public readonly Rsa Rsa;
        public string Message = "Hello!";
        public List<BigInteger> CipherList;

        public MyData()
        {
            Rsa = new Rsa(P, Q, _e, _d);
        }

        public void DecryptMyData(List<BigInteger> cipherList)
        {
            CipherList = cipherList;
            Message = Rsa.Decrypt(cipherList);
        }

        public void EncryptMyData(string message)
        {
            Message = message ?? Message;
            CipherList = Rsa.Encrypt(Message);
        }
    }
}
