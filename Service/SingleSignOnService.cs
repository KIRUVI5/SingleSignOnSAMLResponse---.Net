using Microsoft.Extensions.Options;
using SingleSignONSAMLResponse.Interfaces;
using SingleSignONSAMLResponse.SingleSignOn;
using SingleSignONSAMLResponse.SingleSignOn.Helper;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace SingleSignONSAMLResponse.Service
{
    public class SingleSignOnService : ISingleSignOnService
    {
        public readonly SingleSignOnConfiguration _options;

        private const string XsiSchema = @"http://www.w3.org/2001/XMLSchema-instance";
        private const string XsdSchema = @"http://www.w3.org/2001/XMLSchema";
        private const string IdPrefix = "_";
        private const string UriFormat = "{0}://{1}";

        public SingleSignOnService(IOptions<SingleSignOnConfiguration> optionsAccessor)
        {
            _options = optionsAccessor.Value;
        }

        /// <summary>
        /// Build SAML 2.0 base64 encoded response
        /// </summary>
        /// <param name="personID"></param>
        /// <returns></returns>
        public string BuildEncodedSamlResponse()
        {
            //create attributes
            var attributes = GetAssertationForSaml();

            //setup audience url (service provider)
            Uri audienceUri = new Uri(_options.Domain);

            var settings = new SamlIntegrationSettings(
                _options.Recipient,
                _options.Issuer,
                string.Format(UriFormat, audienceUri.Scheme, audienceUri.Host),
                _options.FindValue,
                 prependToId: IdPrefix
                );

            settings.Attributes = attributes;

            //encoded saml 2.0 response
            var encodedstring = BuildAndSignSamlResponse(settings);

            return encodedstring;
        }

        /// <summary>
        /// Decode encoded saml 2.0 response and get actual XML 
        /// </summary>
        /// <param name="samlToken"></param>
        /// <returns></returns>
        public string DecodeSamlResponse(string samlToken)
        {
            return Base64DecodeString(samlToken);
        }

        /// <summary>
        /// validate Assertation Signature from the encoded saml response
        /// </summary>
        /// <param name="samlToken"></param>
        /// <returns></returns>
        public bool ValidateSamlAssertationSignature(string samlToken)
        {
            var samlString = DecodeSamlResponse(samlToken);

            XmlDocument xmlDoc = new XmlDocument();

            xmlDoc.LoadXml(samlString);

            return IsValidSignature(xmlDoc);
        }

        #region Private Methods
        /// <summary>
        /// Create attributes for assertation
        /// </summary>
        /// <param name="personID"></param>
        /// <returns></returns>
        private Dictionary<string, string> GetAssertationForSaml()
        {
            Dictionary<string, string> attributes = new Dictionary<string, string>()
            {
                {"CompanyID", "2767" },
                {"Identifier", "721095"},
                {"WorkEmail", "vimalan@gmail.com"},
                {"FirstName", "Vimalan"},
                {"LastName", "Kumarakulasinga"},
                {"AddressLine1", "Wellawatta"},
                {"AddressLine2", "Colombo 6"},
                {"AddressLine3", "Colombo" },
                {"AddressLine4", "" },
                {"Postcode", "00006"}
            };

            return attributes;
        }

        /// <summary>
        /// Generate base64 encoded string
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        private string Base64EncodeString(string value, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.ASCII;

            return Convert.ToBase64String(encoding.GetBytes(value));
        }

        /// <summary>
        /// Decode base64 encoded string
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        private string Base64DecodeString(string value, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.ASCII;

            return encoding.GetString(Convert.FromBase64String(value));
        }

        /// <summary>
        /// Validate Signature from saml 2.0 XML
        /// </summary>
        /// <param name="xmlDoc"></param>
        /// <returns></returns>
        private bool IsValidSignature(XmlDocument xmlDoc)
        {
            SignedXml signedXml = new SignedXml(xmlDoc);
            XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");

            if (nodeList != null && nodeList.Count > 0)
            {
                signedXml.LoadXml((XmlElement)nodeList[0]);
                return signedXml.CheckSignature();
            }
            return false;
        }
        #endregion

        #region SAML Response Algorithms
        /// <summary>
        /// create SAML response
        /// </summary>
        /// <param name="samlResponseSpecification"></param>
        /// <param name="assertion"></param>
        /// <returns></returns>
        private ResponseType CreateSamlResponse(SamlIntegrationSettings samlResponseSpecification, AssertionType assertion)
        {
            return new ResponseType
            {
                ID = samlResponseSpecification.PrependToId + Guid.NewGuid().ToString(),
                Issuer = new NameIDType
                {
                    Value = samlResponseSpecification.Issuer
                },
                IssueInstant = DateTime.UtcNow,
                Destination = samlResponseSpecification.Recipient,
                Version = "2.0",
                Status =
                    new StatusType
                    {
                        StatusCode = new StatusCodeType
                        {
                            Value = "urn:oasis:names:tc:SAML:2.0:status:Success"
                        }
                    },
                Items = new object[]
                {
                    assertion
                }
            };
        }

        /// <summary>
        /// signing the SAML response with X.509 certificate
        /// Currently this implementation is not using, but in the future if we want to sign the response; we can use the implementation
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="responseId"></param>
        /// <param name="xmlSamlResponse"></param>
        /// <returns></returns>
        private bool SignSamlResponse(string thumbprint, string responseId, ref XmlDocument xmlSamlResponse)
        {
            //x509 = X509CertificateHelper.GetCertificateByThumbprint(thumbprint, StoreName.My, StoreLocation.LocalMachine);

            var x509 = X509CertificateHelper.GetX509CertificateByPath(_options.X509CertPath, _options.X509CertPassword);

            bool result;

            if (x509 != null)
            {

                SamlSignedXml samlSignedXml = SigningHelper.SignXml(xmlSamlResponse, x509, "ID", responseId);

                // Get the XML representation of the signature and save it to an XmlElement object. 
                XmlElement xmlDigitalSignature = samlSignedXml.GetXml();

                // Put the sign as the first child of main Request tag.
                if (xmlSamlResponse.DocumentElement != null)
                {
                    xmlSamlResponse.DocumentElement.InsertAfter(xmlDigitalSignature,
                        xmlSamlResponse.DocumentElement.ChildNodes[0]);
                }

                result = true;
            }
            else
            {
                x509?.Reset();

                throw new ArgumentException("X509 certificate not found!");
            }

            x509?.Reset();

            return result;
        }

        /// <summary>
        /// serialize the sring to XML
        /// </summary>
        /// <param name="samlResponse"></param>
        /// <returns></returns>
        private XmlDocument SerializeToXml(ResponseType samlResponse)
        {
            string serializedXml;

            using (var stringWriter = new StringWriter(CultureInfo.InvariantCulture))
            {
                var settings = new XmlWriterSettings
                {
                    OmitXmlDeclaration = true,
                    Indent = false,
                    Encoding = System.Text.Encoding.ASCII
                };

                using (var responseWriter = XmlWriter.Create(stringWriter, settings))
                {
                    XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
                    ns.Add("xsi", XsiSchema);
                    ns.Add("xsd", XsdSchema);
                    ns.Add("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
                    ns.Add("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

                    XmlSerializer samlResponseSerializer = new XmlSerializer(samlResponse.GetType());
                    samlResponseSerializer.Serialize(responseWriter, samlResponse, ns);

                    serializedXml = stringWriter.ToString();
                }
            }

            var document = new XmlDocument();
            document.LoadXml(serializedXml);

            return document;
        }

        #endregion

        #region SAML Assertation Algorithms
        /// <summary>
        /// create assertation for saml response
        /// </summary>
        /// <param name="settings"></param>
        /// <param name="userEmail"></param>
        /// <returns></returns>
        private AssertionType CreateAssertation(SamlIntegrationSettings settings)
        {
            //Add attributes XML node into SAML XML
            var items = new List<AttributeType>();
            foreach (var attribute in settings.Attributes)
            {
                var attr = new AttributeType
                {
                    Name = attribute.Key,
                    NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                    AttributeValue = new object[] { attribute.Value }
                };

                items.Add(attr);
            }

            //add Conditions xml node into saml xml
            var conditions = new List<ConditionAbstractType>();
            conditions.Add(new OneTimeUseType());
            conditions.Add(new AudienceRestrictionType
            {
                Audience = new string[] { settings.Audience }
            });

            // Create assertion instance
            string assertionId = IdPrefix + Guid.NewGuid().ToString();
            DateTime issueTime = DateTime.UtcNow;

            //add assertation xml node into saml xml
            AssertionType assertion = new AssertionType
            {
                ID = assertionId,
                IssueInstant = issueTime,
                Version = "2.0",
                Issuer = new NameIDType
                {
                    Value = settings.Issuer
                },
                Subject = new SubjectType
                {
                    Items = new object[]
                    {
                        new NameIDType
                        {
                            Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
                            Value = settings.Attributes["WorkEmail"]
                        },
                        new SubjectConfirmationType
                        {
                            Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer",
                            SubjectConfirmationData = new SubjectConfirmationDataType
                            {
                                NotOnOrAfter = issueTime.AddMinutes(5),
                                NotOnOrAfterSpecified = true,
                                Recipient = settings.Recipient
                            }
                        }
                    }
                },
                Conditions = new ConditionsType
                {
                    NotBefore = issueTime,
                    NotBeforeSpecified = true,
                    NotOnOrAfter = issueTime.AddMinutes(5),
                    NotOnOrAfterSpecified = true,
                    Items = conditions.ToArray()
                },
                Items = new StatementAbstractType[]
                {
                    new AuthnStatementType
                    {
                        AuthnInstant = issueTime,
                        SessionIndex = assertionId,
                        AuthnContext = new AuthnContextType
                        {
                            ItemsElementName = new [] { ItemsChoiceType5.AuthnContextClassRef },
                            Items = new object[] { "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword" }
                        }
                    },
                    new AttributeStatementType
                    {
                        // ReSharper disable once CoVariantArrayConversion
                        Items = items.ToArray()
                    }
                }
            };

            return assertion;
        }

        /// <summary>
        /// Signin SAML assertation with X.509 certificate
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="responseId"></param>
        /// <param name="xmlAssertion"></param>
        /// <returns></returns>
        private bool SignForSamlAssertation(string thumbprint, string responseId, ref XmlElement xmlAssertion)
        {
            X509Certificate2 x509 = null;
            bool result = false;

            // x509 = X509CertificateHelper.GetCertificateByThumbprint(thumbprint, StoreName.My, StoreLocation.LocalMachine);

            x509 = X509CertificateHelper.GetX509CertificateByPath(_options.X509CertPath, _options.X509CertPassword);

            if (x509 != null)
            {

                SamlSignedXml samlSignedElement = SigningHelper.SignXml(xmlAssertion, x509, "ID", responseId);

                // Get the XML representation of the signature and save it to an XmlElement object. 
                XmlElement xmlDigitalSignature = samlSignedElement.GetXml();

                // Put the sign as the first child of main Request tag.
                xmlAssertion?.InsertAfter(xmlDigitalSignature, xmlAssertion.ChildNodes[0]);

                result = true;
            }
            else
            {
                x509?.Reset();

                throw new ArgumentException("X509 certificate not found!");
            }

            x509?.Reset();

            return result;
        }

        /// <summary>
        /// Encript SAML assertion
        /// Currently not in Use - Can use in future if we need
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="xmlDocument"></param>
        /// <returns></returns>
        private bool Encrypt(string thumbprint, ref XmlDocument xmlDocument)
        {
            X509Certificate2 x509 = null;
            bool result = false;

            try
            {
                //x509 = X509CertificateHelper.GetCertificateByThumbprint(thumbprint, StoreName.My, StoreLocation.LocalMachine);

                x509 = X509CertificateHelper.GetX509CertificateByPath(_options.X509CertPath, _options.X509CertPassword);

                if (x509 == null)
                {
                    XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
                    namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
                    namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                    namespaceManager.AddNamespace("xsi", XsiSchema);
                    namespaceManager.AddNamespace("xsd", XsdSchema);

                    XmlElement xmlAssertionSource =
                        (XmlElement)xmlDocument.SelectSingleNode("/samlp:Response/saml:Assertion", namespaceManager);

                    EncryptedXml eXml = new EncryptedXml();

                    var encryptedData = eXml.Encrypt(xmlAssertionSource, x509);

                    XmlDocument encryptedAssertion = new XmlDocument();

                    // Add namespaces
                    XmlDeclaration xmlDeclaration = encryptedAssertion.CreateXmlDeclaration("1.0", "UTF-8", null);
                    XmlElement encryptedRoot = encryptedAssertion.DocumentElement;
                    encryptedAssertion.InsertBefore(xmlDeclaration, encryptedRoot);

                    // Form Assertion element
                    XmlElement encryptedAssertionElement = encryptedAssertion.CreateElement("saml",
                        "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
                    encryptedAssertion.AppendChild(encryptedAssertionElement);

                    // Add encrypted content
                    var encryptedDataNode = encryptedAssertion.ImportNode(encryptedData.GetXml(), true);
                    encryptedAssertionElement.AppendChild(encryptedDataNode);

                    // Form a document
                    var root = xmlDocument.DocumentElement;
                    var node = root.OwnerDocument.ImportNode(encryptedAssertionElement, true);
                    root.RemoveChild(xmlAssertionSource ?? throw new InvalidOperationException());
                    root.AppendChild(node);

                    result = true;
                }
                else
                {
                    throw new ArgumentException("X509 certificate not found!");
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                x509?.Reset();
            }

            return result;
        }

        #endregion

        #region SAML integration steps
        /// <summary>
        /// Create SAML 2.0 encoded resonse with sign assertation
        /// </summary>
        /// <param name="settings"></param>
        /// <returns></returns>
        private string BuildAndSignSamlResponse(SamlIntegrationSettings settings)
        {
            //create SAML assertation
            AssertionType assertion = CreateAssertation(settings);

            //create SAML response
            var samlResponse = CreateSamlResponse(settings, assertion);

            //serialize string to XML
            var xmlSamlResponse = SerializeToXml(samlResponse);

            //Serialize assertion to XML
            XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmlSamlResponse.NameTable);
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            namespaceManager.AddNamespace("xsi", XsiSchema);
            namespaceManager.AddNamespace("xsd", XsdSchema);

            XmlElement xmlAssertion = (XmlElement)xmlSamlResponse.SelectSingleNode("/samlp:Response/saml:Assertion", namespaceManager);

            // Sign assertion
            if (!SignForSamlAssertation(settings.CertificateThumbprint, assertion.ID, ref xmlAssertion))
            {
                throw new ArgumentException("Unable to sign SAML assertion!");
            }

            // Encrypt assertion
            // In the future, If we want to encript our assertation with encripted certificate, we can do by using this feature
            if (!string.IsNullOrWhiteSpace(settings.AssertionEncryptionCertificateThumbprint) &&
                !Encrypt(settings.AssertionEncryptionCertificateThumbprint, ref xmlSamlResponse))
            {
                throw new ArgumentException("Unable to encrypt SAML assertion!");
            }

            // Sign Response
            //In the future, if we want to sign the saml response we can use the this implementation to sign saml
            //if (!SignSamlResponse(settings.CertificateThumbprint, samlResponse.ID, ref xmlSamlResponse))
            //{
            //    _logger.LogDebug("Unable to sign SAML response!");

            //    return null;
            //}

            string result = xmlSamlResponse.OuterXml;

            //Encode saml xml string into base64
            return Base64EncodeString(result);
        }
        #endregion
    }
}
