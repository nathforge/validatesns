"""
Validate integrity of AWS SNS messages.

* Verifies cryptographic signature.
* Checks signing certificate is hosted on an AWS-controlled URL.
* Requires message be no older than one hour, the maximum lifetime of an SNS message.
"""

from __future__ import print_function

import base64
import datetime
import re

import oscrypto.asymmetric
import oscrypto.errors
import six
from six.moves.urllib.request import urlopen

DEFAULT_CERTIFICATE_URL_REGEX = r"^https://sns\.[-a-z0-9]+\.amazonaws\.com(?:\.cn)?/"
DEFAULT_MAX_AGE = datetime.timedelta(hours=1)

class ValidationError(Exception):
    """
    ValidationError. Raised when a message fails integrity checks.
    """

def validate(
    message,
    get_certificate_str=lambda url: urlopen(url).read(),
    certificate_url_regex=DEFAULT_CERTIFICATE_URL_REGEX,
    max_age=DEFAULT_MAX_AGE
):
    """
    Validate a decoded SNS message.

    Parameters:
        message:
            Decoded SNS message.

        get_certificate_str:
            Function that receives a URL, and returns the certificate from that
            URL as a string. The default doesn't implement caching.

        certificate_url_regex:
            Regex that validates the signing certificate URL. Default value
            checks it's hosted on an AWS-controlled domain, in the format
            "https://sns.<data-center>.amazonaws.com/"

        max_age:
            Maximum age of an SNS message before it fails validation, expressed
            as a `datetime.timedelta`. Defaults to one hour, the max. lifetime
            of an SNS message.
    """

    # Check the signing certicate URL.
    SigningCertURLValidator(certificate_url_regex).validate(message)

    # Check the message age.
    if not isinstance(max_age, datetime.timedelta):
        raise ValueError("max_age must be None or a timedelta object")
    MessageAgeValidator(max_age).validate(message)

    # Passed the basic checks, let's download the cert.
    # We've validated the URL, so aren't worried about a malicious server.
    certificate_str = get_certificate_str(message["SigningCertURL"])

    # Check the cryptographic signature.
    SignatureValidator(certificate_str).validate(message)

class SigningCertURLValidator(object):
    """
    Validate a message's SigningCertURL is in the expected format.
    """

    def __init__(self, regex=DEFAULT_CERTIFICATE_URL_REGEX):
        self.regex = regex

    def validate(self, message):
        if not isinstance(message, dict):
            raise ValidationError("Unexpected message type {!r}".format(type(message).__name__))

        url = message.get("SigningCertURL")

        if isinstance(url, six.string_types) and re.search(self.regex, url):
            return

        raise ValidationError("SigningCertURL {!r} doesn't match required format {!r}".format(url, self.regex))

class MessageAgeValidator(object):
    """
    Validate a message is not too old.
    """

    def __init__(self, max_age=DEFAULT_MAX_AGE):
        self.max_age = max_age

    def validate(self, message):
        if not isinstance(message, dict):
            raise ValidationError("Unexpected message type {!r}".format(type(message).__name__))

        utc_now = datetime.datetime.utcnow()

        utc_timestamp = self._get_utc_timestamp(message)

        age = utc_now - utc_timestamp
        if age <= self.max_age:
            return

        raise ValidationError("Message is too old: {}".format(age))

    def _get_utc_timestamp(self, message):
        utc_timestamp_str = message.get("Timestamp")
        if not isinstance(utc_timestamp_str, six.string_types):
            raise ValidationError("Expected Timestamp to be a string, but received {!r}".format(utc_timestamp_str))

        try:
            utc_timestamp = datetime.datetime.strptime(utc_timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            raise ValidationError("Unexpected Timestamp format {!r}".format(utc_timestamp_str))

        return utc_timestamp

class SignatureValidator(object):
    """
    Validate a message's cryptographic signature.

    AWS docs: http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html
    """

    def __init__(self, certificate_str):
        self.certificate_str = certificate_str

    def validate(self, message):
        if not isinstance(message, dict):
            raise ValidationError("Unexpected message type {!r}".format(type(message).__name__))

        signature_version = message.get("SignatureVersion")
        if signature_version != "1":
            raise ValidationError("Unexpected SignatureVersion {!r}".format(signature_version))

        signature = base64.b64decode(message["Signature"])

        signing_content = self._get_signing_content(message)

        self._validate_signature(signature, signing_content)

    def _validate_signature(self, signature, content):
        cert = oscrypto.asymmetric.load_certificate(self.certificate_str)
        try:
            oscrypto.asymmetric.rsa_pkcs1v15_verify(cert, signature, content.encode("utf8"), "sha1")
        except oscrypto.errors.SignatureError:
            raise ValidationError("Invalid signature")

    def _get_signing_content(self, message):
        lines = []
        for key in self._get_signing_keys(message):
            if key not in message:
                raise ValidationError("Missing {!r} key".format(key))

            lines.append(key)
            lines.append(message[key])

        return "\n".join(lines) + "\n"

    def _get_signing_keys(self, message):
        message_type = message.get("Type")

        if message_type == "Notification":
            if "Subject" in message:
                return ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
            else:
                return ("Message", "MessageId", "Timestamp", "TopicArn", "Type",)

        if message_type in ("SubscriptionConfirmation", "UnsubscribeConfirmation"):
            return ("Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type")

        raise ValidationError("Unknown message type {!r}".format(message_type))
