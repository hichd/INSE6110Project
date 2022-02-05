using Cryptos;
using RSA.Cryptos.utils;
using System.Collections.Generic;
using System.Numerics;
using utils;

namespace Profiles
{
    public class PartnerDataProfile : BaseDataProfile
    {
        public List<BigInteger> SignatureInts { get; set; }
        public string OriginalSignedMessage { get; set; }

        public PartnerDataProfile()
        {
            N = new BigInteger(3329945081);
            _e = new BigInteger(1520147791);
            Rsa = new Rsa(_e, N);
            ID = 40219703;
            Message = "RSA";

            // Encrypt message for partner
            EncryptMessage();

            // partner's signature integer representation
            SignatureInts = new List<BigInteger>
            {
                2113949826, 1963951462, 2738011418, 1425672423, 636141482
            };
            // partner's signed original message
            OriginalSignedMessage = "Alex Le Blanc";
            Signature = $"['{string.Join("', '", SignatureInts)}']";

            // partner's signature verification operation
            var resultList = new List<BigInteger>();
            foreach(var signatureInt in SignatureInts)
            {
                var result = CryptoUtility.SquareAndMultiply(signatureInt, _e, N, false);
                resultList.Add(result);
            }
            MessageToSign = resultList.BigIntegerToString();
        }
    }
}
