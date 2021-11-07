using Cryptos;
using System.Numerics;

namespace Profiles
{
    public class PartnerDataProfile : BaseDataProfile
    {
        public PartnerDataProfile()
        {
            N = new BigInteger(1282997161);
            _e = new BigInteger(311);
            Rsa = new Rsa(_e, N);
            ID = 1111111;
            Message = "The many saints of newark";
        }
    }
}
