using Cryptos;
using System.Collections.Generic;
using System.Numerics;

namespace RSA.Profiles
{
    public class PartnerData
    {
        public readonly BigInteger N = new BigInteger(1282997161);
        public readonly BigInteger _e = new BigInteger(311);
        public string Message = "Hello!";
        public readonly Rsa Rsa;
        public List<BigInteger> CipherList;
        public string Cipher;

        public string Name;

        public PartnerData()
        {
            Rsa = new Rsa(_e, N);
        }

        private void EncryptPartnerData(string message)
        {
            Message = message ?? Message;
            CipherList = Rsa.Encrypt(Message);
            Cipher = string.Join("\n", CipherList);
        }

        public string GenerateEncryptedMessageForPartner(string message = null)
        {
            EncryptPartnerData(message);
            return Cipher;
        }
    }
}
