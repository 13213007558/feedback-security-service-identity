"""
An example of how to use service_identity to verify SPIFFE IDs.

.. note::
   Only the *identity* is verified here.
   Whether the certificate *chain* is trusted is up to your own chain
   verification -- service_identity does not (and can not) do that for you.
"""

from cryptography.x509 import load_pem_x509_certificate

from service_identity.cryptography import verify_certificate_spiffe_id


cert = load_pem_x509_certificate(pem_data)

# Raises VerificationError if the certificate does not contain exactly this
# SPIFFE ID, or if "example.com" is not a trust domain you decided to allow.
# The certificate's contents can never widen that set.
matches = verify_certificate_spiffe_id(
    cert,
    "spiffe://example.com/ns/default/sa/web",
    allowed_trust_domains=["example.com"],
)

# The matches carry the full matched identity (trust domain and path).
print(matches[0].cert_pattern.trust_domain)
print(matches[0].cert_pattern.path)
