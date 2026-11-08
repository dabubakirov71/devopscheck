"""
The allauth social signup form, told up front when the email is taken.

allauth only reports "an account already exists with this email" after the
visitor presses Create account. GitLab does not tell allauth the email is
verified, so a GitLab sign-in by someone who already has an account here
always lands on this form — pre-filled with their own email, inviting them
to make a duplicate. `email_taken` lets the template explain the way in
(sign in, then connect) before they try.
"""
from allauth.account.models import EmailAddress
from allauth.socialaccount.forms import SignupForm
from django.contrib.auth import get_user_model


class SocialSignupForm(SignupForm):

    @property
    def email_taken(self) -> bool:
        email = (self.initial.get('email') or '').strip()
        if not email:
            return False
        return (EmailAddress.objects.filter(email__iexact=email).exists()
                or get_user_model().objects.filter(email__iexact=email).exists())
