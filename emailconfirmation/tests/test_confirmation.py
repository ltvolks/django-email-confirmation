import os
import re

from django.conf import settings
from django.core import mail
from django.core.urlresolvers import reverse
from django.test import TestCase

from django.contrib.auth.models import User

from emailconfirmation.models import EmailAddress, EmailConfirmation

"""
Tests:
    Unexpired Confirmations should be reused when generating or sending
    Clicking Re-Send should reuse or create a new EmailConfirmation and add to the queue
    
"""
class EmailAddressTest(TestCase):
    
    def setUp(self):
        self.old_installed_apps = settings.INSTALLED_APPS
        # remove django-mailer to properly test for outbound e-mail
        if "mailer" in settings.INSTALLED_APPS:
            settings.INSTALLED_APPS.remove("mailer")
    
    def tearDown(self):
        settings.INSTALLED_APPS = self.old_installed_apps
    
    def context_lookup(self, response, key):
        # used for debugging
        for subcontext in response.context:
            if key in subcontext:
                return subcontext[key]
        raise KeyError


    def test_add_email_defaults(self):
        """
        New EmailAddress instances should default to primary and unverified
        """
        dummy = User.objects.create_user("dummy", "dummy@example.com", "abc123")
        email_address = EmailAddress.objects.create(
            user = dummy,
            email = "dummy@example.com"
        )

        self.assertEquals(email_address.verified, False)
        self.assertEquals(email_address.primary, True)


    def test_email_manager(self):
        """
        EmailAddressManager additional methods:
            add_email - Add an email and automatically generate a confirmation key
        """
        dummy = User.objects.create_user("dummy", "dummy@example.com", "abc123")
        email_address = EmailAddress.objects.add_email(
            user = dummy,
            email = "dummy@example.com",
            send_confirm = False
        )
        
        confirmations = email_address.confirmations.all()
        self.assertTrue(len(confirmations) == 1)

        # Creating another confirmation should return the existing if not expired


    def test_redundant_confirmations(self):
        """
        Multiple confirmations can be created and sent to the user.
        Once the email is confirmed, any of the other confirmations will be ignored
        """
        dummy = User.objects.create_user("dummy", "dummy@example.com", "abc123")
        email_address = EmailAddress.objects.add_email(
            user = dummy,
            email = "dummy@example.com",
            send_confirm = False
        )
        confirmations = email_address.confirmations.all()
        self.assertTrue(len(confirmations) == 1)

        # Create another confirmation
        confirmation = email_address.confirmations.generate_confirmation(email_address)
        confirmations = email_address.confirmations.all()
        self.assertTrue(len(confirmations) == 2)

        # Confirm email
        ret_email = EmailConfirmation.objects.confirm_email(confirmation.confirmation_key)
        self.assertEqual(ret_email, email_address)
        self.assertTrue(email_address.confirmations.count() == 0)

        email_address = EmailAddress.objects.get(id=ret_email.id)
        self.assertTrue(email_address.verified)
        


