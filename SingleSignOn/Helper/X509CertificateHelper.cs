using System.Security.Cryptography.X509Certificates;

namespace SingleSignONSAMLResponse.SingleSignOn.Helper
{
    public static class X509CertificateHelper
    {
        /// <summary>
        /// Returns first certificate in specified store found by thumbprint.
        /// </summary>
        /// <exception cref="SecurityException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection storeCollection = store.Certificates;
            X509Certificate2Collection certificates = storeCollection.Find(X509FindType.FindByThumbprint, thumbprint, false);

            X509Certificate2 certificate;
            if (certificates.Count > 0)
            {
                certificate = certificates[0];  // Take first and work done.
            }
            else
            {
                if (store != null)
                {
                    store.Close();
                }

                throw new ArgumentException("X509 certificate not found!");
            }

            if (store != null)
            {
                store.Close();
            }

            return certificate;
        }

        /// <summary>
        /// Get X.509 Certificate from the patha
        /// </summary>
        /// <param name="pfxFilePath"></param>
        /// <param name="certPassword"></param>
        /// <returns></returns>
        public static X509Certificate2 GetX509CertificateByPath(string pfxFilePath, string certPassword)
        {
            return new X509Certificate2(File.ReadAllBytes(pfxFilePath), certPassword);
        }
    }
}
