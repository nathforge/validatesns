===========
validatesns
===========

Validate integrity of Amazon SNS messages.

* Verifies cryptographic signature.
* Checks signing certificate is hosted on an Amazon-controlled URL.
* Requires message be no older than one hour, the maximum lifetime of an SNS message.

|CILink|_

Licence: MIT_.


***********
Quick start
***********

.. code-block:: shell

   $ pip install validatesns

.. code-block:: python

   import validatesns

   # Raise validatesns.ValidationError if message is invalid.
   validatesns.validate(decoded_json_message_from_sns)


*******
Gotchas
*******

The ``validate`` function downloads the signing certificate on every call. For performance reasons, it's worth caching certificates - you can do this by passing in a ``get_certificate_str`` function.

This takes a ``url``, and returns the certificate content. Your function could cache to the filesystem, a database, or wherever makes sense.


**********
Contribute
**********

Github: https://github.com/nathforge/validatesns

.. |CILink| image:: https://travis-ci.org/nathforge/validatesns.svg?branch=master
.. _CILink: https://travis-ci.org/nathforge/validatesns
.. _MIT: https://opensource.org/licenses/MIT
