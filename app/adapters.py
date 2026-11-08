"""
allauth adapter: when a social sign-in may land in an existing account.

With `SOCIALACCOUNT_EMAIL_AUTHENTICATION` on, someone who signed up with
Google and later presses "Continue with GitHub" is signed in to the account
they already have, instead of being asked to create a second one — which,
with the old signup stub, meant being bounced back to the login page.

allauth already requires the *provider* to vouch for the email. This also
requires *our* side to have verified it. `views.register_view` takes any email
without confirming it, so without this check a person could register with
someone else's address and wait for that person's first GitHub sign-in to
walk into the account they prepared.
"""
from allauth.account.models import EmailAddress
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class SocialAccountAdapter(DefaultSocialAccountAdapter):

    def can_authenticate_by_email(self, login, email):
        if not super().can_authenticate_by_email(login, email):
            return False
        return EmailAddress.objects.filter(email__iexact=email, verified=True).exists()
