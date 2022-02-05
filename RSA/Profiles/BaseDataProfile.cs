using Cryptos;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace Profiles
{
    public class BaseDataProfile
    {
        public BigInteger N;
        public BigInteger _e;
        public string Message;
        public string MessageChunks;
        public Rsa Rsa;
        public List<BigInteger> CipherList;
        public string Cipher;
        public int ID;
        public string MessageToSign { get; set; }
        public string MessageToSignChunks { get; set; }
        public string Signature { get; set; }

        public List<BigInteger> EncryptMessage(string message = null)
        {
            Message = message ?? Message;
            MessageChunks = $"['{string.Join("', '", Message.ChunksUpto(3))}']";
            CipherList = Rsa.Encrypt(Message);
            Cipher = $"[{string.Join(", ", CipherList)}]";
            return CipherList;
        }
    }
}
