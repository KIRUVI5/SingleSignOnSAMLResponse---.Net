namespace SingleSignONSAMLResponse.Interfaces
{
    public interface ISingleSignOnService
    {
        string BuildEncodedSamlResponse();
        string DecodeSamlResponse(string samlToken);
        bool ValidateSamlAssertationSignature(string samlToken);
    }
}
