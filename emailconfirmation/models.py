import datetime
from random import random

from django.conf import settings
from django.db import models, IntegrityError
from django.core.mail import send_mail
from django.core.urlresolvers import reverse, NoReverseMatch
from django.template.loader import render_to_string
from django.utils.hashcompat import sha_constructor
from django.utils.translation import gettext_lazy as _

from django.contrib.sites.models import Site
from django.contrib.auth.models import User

from emailconfirmation.signals import email_confirmed, email_confirmation_sent

# this code based in-part on django-registration

class EmailAddressManager(models.Manager):

    def add_email(self, user, email, primary=False, send_confirm=True):
        """Add a user email record, create and send an email confirmation

        A confirmation key is always generated and associated with the address,
        even if the confirmation is not sent.
        
        :param user: User instance
        :param email: Email address
        :type email: string
        :param primary: Set address as primary (default=False)
        :type primary: boolean or None
        :param send_confirm: Automatically send the confirmation. If False, confirmation
        is created, but will not be sent.
        :type send_confirm: boolean or None
        :returns: EmailAddress instance
        """
        try:
            email_address = self.create(user=user, email=email, primary=primary)
        except IntegrityError:
            return None
        else:
            confirmation = EmailConfirmation.objects.generate_confirmation(email_address)
            if send_confirm:
                EmailConfirmation.objects.send_confirmation(confirmation)
            return email_address
            
    def get_primary(self, user):
        try:
            return self.get(user=user, primary=True)
        except EmailAddress.DoesNotExist:
            return None

    def get_users_for(self, email):
        """
        returns a list of users with the given email.
        """
        # this is a list rather than a generator because we probably want to
        # do a len() on it right away
        return [address.user for address in EmailAddress.objects.filter(
            verified=True, email=email)]


class EmailAddress(models.Model):
    
    user = models.ForeignKey(User)
    email = models.EmailField()
    verified = models.BooleanField(default=False)
    primary = models.BooleanField(default=False)
    
    objects = EmailAddressManager()
    
    def set_as_primary(self, conditional=False):
        """Set address as primary for the User

        :param conditional: If True, will only set as primary if there
        is no existing primary email for the User
        :type conditional: boolean or None
        :rtype: boolean, True if set as primary
        """
        old_primary = EmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        self.primary = True
        self.save()
        self.user.email = self.email
        self.user.save()
        return True

    def latest_confirmation(self):
        """Return latest confirmation for this address or generate a new one
        
        :return: EmailConfirmation instance
        """
        try:
            confirmation = EmailConfirmation.objects.filter(email_address=self).latest('sent')
        except EmailConfirmation.DoesNotExist:
            confirmation = EmailConfirmation.objects.generate_confirmation(self)
        return confirmation
        
    def __unicode__(self):
        return u"%s (%s)" % (self.email, self.user)
    
    def save(self, *args, **kwargs):
        if EmailAddress.objects.get_primary(self.user) is None:
            self.primary = True
        if self.primary:
            self.user.email = self.email
            self.user.save()
        super(EmailAddress, self).save(*args, **kwargs)
    
    class Meta:
        verbose_name = _("e-mail address")
        verbose_name_plural = _("e-mail addresses")
        unique_together = (
            ("user", "email"),
        )


class EmailConfirmationManager(models.Manager):
    
    def confirm_email(self, confirmation_key):
        """Set confirmed status for email
        Redundant confirmations will be deleted, invalidating them.
        
        :param confirmation_key: hexadecimal string - a secure hash as 
                                 returned by hashlib.sha1().hexdigest()
        :return: None or confirmed EmailAddress
        """
        try:
            confirmation = self.get(confirmation_key=confirmation_key)
        except self.model.DoesNotExist:
            return None
        if not confirmation.key_expired():
            email_address = confirmation.email_address
            email_address.verified = True
            email_address.set_as_primary(conditional=True)
            email_address.save()
            email_confirmed.send(sender=self.model, email_address=email_address)

            # Delete all confirmations for this email
            confirmations = self.filter(email_address=email_address).delete()
            
            return email_address


    def generate_confirmation(self, email_address):
        """Generate and return a new EmailConfirmation w/ key.
        #TODO: ? Return existing confirmation and disallow multiple confirmations?
        
        :param email_address: EmailAddress instance
        :return: EmailConfirmation instance
        """
        salt = sha_constructor(str(random())).hexdigest()[:5]
        confirmation_key = sha_constructor(salt + email_address.email).hexdigest()
        confirmation = self.create(
                            email_address=email_address,
                            sent=datetime.datetime.now(),
                            confirmation_key=confirmation_key)

        return confirmation


    def render_confirmation(self, confirmation, subject_tmpl=None, message_tmpl=None):
        """Return rendered confirmation email subject and body

        :param confirmation: EmailConfirmation instance
        :param subject_tmpl: string path to subject template
        :param message_tmpl: string path to message template
        :return: tuple of (subject, message) of email confirmation message
        
        """
        current_site = Site.objects.get_current()
        
        confirmation_key = confirmation.confirmation_key
        activate_url = confirmation.get_activate_url()

        context = {
            "user": confirmation.email_address.user,
            "activate_url": activate_url,
            "current_site": current_site,
            "confirmation_key": confirmation_key,
        }
        subject_tmpl = subject_tmpl or "emailconfirmation/email_confirmation_subject.txt"
        message_tmpl = message_tmpl or "emailconfirmation/email_confirmation_message.txt"
        
        subject = render_to_string(subject_tmpl, context)
        # remove superfluous line breaks
        subject = "".join(subject.splitlines())
        message = render_to_string(message_tmpl, context)

        return (subject, message)

    def send_confirmation(self, confirmation):
        """Send a confirmation email using a previously generated confirmation.
        
        :param confirmation: EmailConfirmation instance
        :return: None
        """

        subject, message = self.render_confirmation(confirmation)

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [confirmation.email_address.email])
        email_confirmation_sent.send(
            sender=self.model,
            confirmation=confirmation,
        )
        return
        

    def delete_expired_confirmations(self):
        """Delete expired EmailConfirmations from the database
        As determined by settings.EMAIL_CONFIRMATION_DAYS

        :return: None
        """
        for confirmation in self.all():
            if confirmation.key_expired():
                confirmation.delete()

class EmailConfirmation(models.Model):

    email_address = models.ForeignKey(EmailAddress, related_name="confirmations")
    sent = models.DateTimeField()
    confirmation_key = models.CharField(max_length=40)
    
    objects = EmailConfirmationManager()
    
    def key_expired(self):
        """Check confirmation key expiration. A key is expired
        if it is older than settings.EMAIL_CONFIRMATION_DAYS
        
        :return: True if confirmation key has expired
        :rtype: boolean
        """
        expiration_date = self.sent + datetime.timedelta(
            days=settings.EMAIL_CONFIRMATION_DAYS)
        return expiration_date <= datetime.datetime.now()
    key_expired.boolean = True


    def get_activate_url(self):
        """Return the activation url for this confirmation
        
        :returns: Activation url for this confirmation
        :rtype: unicode url
        """
        current_site = Site.objects.get_current()
        # check for the url with the dotted view path
        try:
            path = reverse("emailconfirmation.views.confirm_email",
                args=[self.confirmation_key])
        except NoReverseMatch:
            # or get path with named urlconf instead
            path = reverse(
                "emailconfirmation_confirm_email", args=[self.confirmation_key])
        
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        activate_url = u"%s://%s%s" % (
            protocol,
            unicode(current_site.domain),
            path
        )
        return activate_url

    def __unicode__(self):
        return u"confirmation for %s" % self.email_address
    
    class Meta:
        verbose_name = _("e-mail confirmation")
        verbose_name_plural = _("e-mail confirmations")
