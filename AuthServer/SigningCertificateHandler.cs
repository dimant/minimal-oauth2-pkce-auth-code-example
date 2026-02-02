using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthServer
{
    public class SigningCertificateHandler
    {
        private readonly X509Certificate2 _certificate;

        public SigningCertificateHandler(string commonName)
        {
            _certificate = GenerateSigningCertificate(commonName);
        }

        /// <summary>
        /// Generates a self-signed X.509 certificate with RSA key pair for signing tokens.
        /// </summary>
        private static X509Certificate2 GenerateSigningCertificate(string commonName)
        {
            using (var rsa = RSA.Create(2048))
            {
                // The CN field means Common Name. It designates the name of the entity
                // associated with the public key stored in the certificate. If we were to
                // request a certificate from a trusted Certificate Authority (CA),
                // the CN field would typically contain the domain name of the website
                // or service. Basically it means 'this certificate was issued to
                // this entity'.
                var request = new CertificateRequest(
                    $"cn={commonName}",
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1
                );

                // Add certificate extensions for token signing
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature,
                        critical: false
                    )
                );

                // Generate self-signed certificate valid for 1 year
                var certificate = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow.AddYears(1)
                );

                return certificate;
            }
        }

        /// <summary>
        /// Gets the public key in PEM format.
        /// </summary>
        public string GetPublicKey()
        {
            var publicKeyBytes = _certificate.PublicKey.EncodedKeyValue.RawData;
            return Convert.ToBase64String(publicKeyBytes);
        }

        /// <summary>
        /// Gets the private key in PEM format.
        /// </summary>
        public string GetPrivateKey()
        {
            var rsa = _certificate.GetRSAPrivateKey() 
                ?? throw new InvalidOperationException("Private key is not available");
            var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
            return Convert.ToBase64String(privateKeyBytes);
        }
    }
}