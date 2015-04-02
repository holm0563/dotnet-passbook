using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Ionic.Zip;
using Newtonsoft.Json;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Passbook.Generator.Exceptions;

namespace Passbook.Generator
{
    public class PassGenerator
    {
        private byte[] passFile = null;
        private byte[] signatureFile = null;
        private byte[] manifestFile = null;
        private byte[] pkPassFile = null;

        private const string APPLE_CERTIFICATE_THUMBPRINT = "‎0950b6cd3d2f37ea246a1aaa20dfaadbd6fe1f75";

        public byte[] Generate(PassGeneratorRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request", "You must pass an instance of PassGeneratorRequest");
            }

            if (request.IsValid)
            {
                CreatePackage(request);
                ZipPackage(request);

                return pkPassFile;
            }
            else
            {
                throw new Exception("PassGeneratorRequest is not valid");
            }
        }

        private void ZipPackage(PassGeneratorRequest request)
        {
            using (MemoryStream zipToOpen = new MemoryStream())
            {
                using (ZipFile zip = new ZipFile())
                {
                    ZipEntry imageEntry = null;

                    if (request.Images.ContainsKey(PassbookImage.Icon))
                    {
                        zip.AddEntry("icon.png", request.Images[PassbookImage.Icon]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.IconRetina))
                    {
                        zip.AddEntry("icon@2x.png", request.Images[PassbookImage.IconRetina]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.Logo))
                    {
                        zip.AddEntry("logo.png", request.Images[PassbookImage.Logo]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.LogoRetina))
                    {
                        zip.AddEntry("logo@2x.png", request.Images[PassbookImage.LogoRetina]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.Background))
                    {
                        zip.AddEntry("background.png", request.Images[PassbookImage.Background]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.BackgroundRetina))
                    {
                        zip.AddEntry("background@2x.png", request.Images[PassbookImage.BackgroundRetina]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.Strip))
                    {
                        zip.AddEntry("strip.png", request.Images[PassbookImage.Strip]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.StripRetina))
                    {
                        zip.AddEntry("strip@2x.png", request.Images[PassbookImage.StripRetina]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.Thumbnail))
                    {
                        zip.AddEntry("thumbnail.png", request.Images[PassbookImage.Thumbnail]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.ThumbnailRetina))
                    {
                        zip.AddEntry("thumbnail@2x.png", request.Images[PassbookImage.ThumbnailRetina]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.Footer))
                    {
                        zip.AddEntry("footer.png", request.Images[PassbookImage.Footer]);
                    }

                    if (request.Images.ContainsKey(PassbookImage.FooterRetina))
                    {
                        zip.AddEntry("footer@sx.png", request.Images[PassbookImage.FooterRetina]);
                    }

                    zip.AddEntry("pass.json", passFile);
                    zip.AddEntry("manifest.json", manifestFile);
                    zip.AddEntry("signature", signatureFile);

                    zip.Save(zipToOpen);
                }

                pkPassFile = zipToOpen.ToArray();
                zipToOpen.Flush();
            }
        }

        private void CreatePackage(PassGeneratorRequest request)
        {
            CreatePassFile(request);
            GenerateManifestFile(request);
        }

        private void CreatePassFile(PassGeneratorRequest request)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (StreamWriter sr = new StreamWriter(ms))
                {
                    using (JsonWriter writer = new JsonTextWriter(sr))
                    {
                        Trace.TraceInformation("Writing JSON...");
                        request.Write(writer);
                    }

                    passFile = ms.ToArray();
                }
            }
        }

        private void GenerateManifestFile(PassGeneratorRequest request)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (StreamWriter sw = new StreamWriter(ms))
                {
                    using (JsonWriter jsonWriter = new JsonTextWriter(sw))
                    {
                        jsonWriter.Formatting = Formatting.Indented;
                        jsonWriter.WriteStartObject();

                        string hash = null;

                        if (request.Images.ContainsKey(PassbookImage.Icon))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.Icon]);
                            jsonWriter.WritePropertyName(@"icon.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.IconRetina))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.IconRetina]);
                            jsonWriter.WritePropertyName(@"icon@2x.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.Logo))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.Logo]);
                            jsonWriter.WritePropertyName(@"logo.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.LogoRetina))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.LogoRetina]);
                            jsonWriter.WritePropertyName(@"logo@2x.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.Background))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.Background]);
                            jsonWriter.WritePropertyName(@"background.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.BackgroundRetina))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.BackgroundRetina]);
                            jsonWriter.WritePropertyName(@"background@2x.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.Strip))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.Strip]);
                            jsonWriter.WritePropertyName(@"strip.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.StripRetina))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.StripRetina]);
                            jsonWriter.WritePropertyName(@"strip@2x.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.Thumbnail))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.Thumbnail]);
                            jsonWriter.WritePropertyName(@"thumbnail.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        if (request.Images.ContainsKey(PassbookImage.ThumbnailRetina))
                        {
                            hash = GetHashForBytes(request.Images[PassbookImage.ThumbnailRetina]);
                            jsonWriter.WritePropertyName(@"thumbnail@2x.png");
                            jsonWriter.WriteValue(hash.ToLower());
                        }

                        hash = GetHashForBytes(passFile);
                        jsonWriter.WritePropertyName(@"pass.json");
                        jsonWriter.WriteValue(hash.ToLower());
                    }

                    manifestFile = ms.ToArray();
                }

                SignManigestFile(request);
            }
        }

        private void SignManigestFile(PassGeneratorRequest request)
        {
            Trace.TraceInformation("Signing the manifest file...");

            X509Certificate2 card = GetCertificate(request);

            if (card == null)
            {
                throw new FileNotFoundException("Certificate could not be found. Please ensure the thumbprint and cert location values are correct.");
            }

            try
            {
                Org.BouncyCastle.X509.X509Certificate cert = DotNetUtilities.FromX509Certificate(card);
                Org.BouncyCastle.Crypto.AsymmetricKeyParameter privateKey = DotNetUtilities.GetKeyPair(card.PrivateKey).Private;

                Trace.TraceInformation("Fetching Apple Certificate for signing..");

                X509Certificate2 appleCA = GetAppleCertificate(request);
                Org.BouncyCastle.X509.X509Certificate appleCert = DotNetUtilities.FromX509Certificate(appleCA);

                Trace.TraceInformation("Constructing the certificate chain..");

                ArrayList intermediateCerts = new ArrayList();

                intermediateCerts.Add(appleCert);
                intermediateCerts.Add(cert);

                Org.BouncyCastle.X509.Store.X509CollectionStoreParameters PP = new Org.BouncyCastle.X509.Store.X509CollectionStoreParameters(intermediateCerts);
                Org.BouncyCastle.X509.Store.IX509Store st1 = Org.BouncyCastle.X509.Store.X509StoreFactory.Create("CERTIFICATE/COLLECTION", PP);

                CmsSignedDataGenerator generator = new CmsSignedDataGenerator();

                generator.AddSigner(privateKey, cert, CmsSignedDataGenerator.DigestSha1);
                generator.AddCertificates(st1);

                Trace.TraceInformation("Processing the signature..");

                CmsProcessable content = new CmsProcessableByteArray(manifestFile);
                CmsSignedData signedData = generator.Generate(content, false);

                signatureFile = signedData.GetEncoded();

                Trace.TraceInformation("The file has been successfully signed!");

            }
            catch (Exception exp)
            {
                Trace.TraceError("Failed to sign the manifest file: [{0}]", exp.Message);
                throw new ManifestSigningException("Failed to sign manifest", exp);
            }
        }

        private X509Certificate2 GetAppleCertificate(PassGeneratorRequest request)
        {
            Trace.TraceInformation("Fetching Apple Certificate...");

            try
            {
                if (request.AppleWWDRCACertificate == null)
                {
                    return GetSpecifiedCertificateFromCertStore(APPLE_CERTIFICATE_THUMBPRINT, StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                }
                else
                {
                    return GetCertificateFromBytes(request.AppleWWDRCACertificate, null);
                }
            }
            catch (Exception exp)
            {
                Trace.TraceError("Failed to fetch Apple Certificate: [{0}]", exp.Message);
                throw;
            }
        }

        public static X509Certificate2 GetCertificate(PassGeneratorRequest request)
        {
            Trace.TraceInformation("Fetching Pass Certificate...");

            try
            {
                if (request.Certificate == null)
                {
                    return GetSpecifiedCertificateFromCertStore(request.CertThumbprint, StoreName.My, request.CertLocation);
                }
                else
                {
                    return GetCertificateFromBytes(request.Certificate, request.CertificatePassword);
                }
            }
            catch (Exception exp)
            {
                Trace.TraceError("Failed to fetch Pass Certificate: [{0}]", exp.Message);
                throw;
            }
        }

        private static X509Certificate2 GetSpecifiedCertificateFromCertStore(string thumbPrint, StoreName storeName, StoreLocation storeLocation)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certs = store.Certificates;

            if (certs.Count > 0)
            {
                for (int i = 0; i < certs.Count; i++)
                {
                    X509Certificate2 cert = certs[i];

                    Debug.WriteLine(cert.Thumbprint);

                    if (string.Compare(cert.Thumbprint, thumbPrint, true) == 0)
                    {
                        return certs[i];
                    }
                }
            }

            return null;
        }

        private static X509Certificate2 GetCertificateFromBytes(byte[] bytes, string password)
        {
            Trace.TraceInformation("Opening Certificate: [{0}] bytes with password [{1}]", bytes.Length, password);

            X509Certificate2 certificate = null;

            if (password == null)
            {
                certificate = new X509Certificate2(bytes);
            }
            else
            {
                X509KeyStorageFlags flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable;
                certificate = new X509Certificate2(bytes, password, flags);
            }

            return certificate;
        }

        private string GetHashForBytes(byte[] bytes)
        {
            SHA1CryptoServiceProvider oSHA1Hasher = new SHA1CryptoServiceProvider();
            byte[] hashBytes;

            hashBytes = oSHA1Hasher.ComputeHash(bytes);

            string hash = System.BitConverter.ToString(hashBytes);
            hash = hash.Replace("-", "");
            return hash;
        }
    }
}
