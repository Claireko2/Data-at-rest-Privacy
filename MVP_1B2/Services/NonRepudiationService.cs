using System.Security.Cryptography;
using System.Text;

namespace MVP_1B2.Services
{
    public sealed class NonRepudiationService
    {
        private readonly RSA _privateKey;
        private readonly RSA _publicKey;

        public NonRepudiationService(IConfiguration configuration)
        {
            var privateKeyBase64 =
                configuration["NonRepudiation:PrivateKey"];

            var publicKeyBase64 =
                configuration["NonRepudiation:PublicKey"];

            if (string.IsNullOrWhiteSpace(privateKeyBase64))
            {
                throw new InvalidOperationException(
                    "NonRepudiation:PrivateKey is not configured.");
            }

            if (string.IsNullOrWhiteSpace(publicKeyBase64))
            {
                throw new InvalidOperationException(
                    "NonRepudiation:PublicKey is not configured.");
            }

            _privateKey = RSA.Create();
            _privateKey.ImportPkcs8PrivateKey(
                Convert.FromBase64String(privateKeyBase64),
                out _);

            _publicKey = RSA.Create();
            _publicKey.ImportSubjectPublicKeyInfo(
                Convert.FromBase64String(publicKeyBase64),
                out _);
        }

        public string Sign(string data)
        {
            byte[] dataBytes =
                Encoding.UTF8.GetBytes(data);

            byte[] signature =
                _privateKey.SignData(
                    dataBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

            return Convert.ToBase64String(signature);
        }

        public bool Verify(string data, string signature)
        {
            byte[] dataBytes =
                Encoding.UTF8.GetBytes(data);

            byte[] signatureBytes =
                Convert.FromBase64String(signature);

            return _publicKey.VerifyData(
                dataBytes,
                signatureBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }
    }
}
