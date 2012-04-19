"""
Management utility to create superusers.
"""

import getpass
import re
import sys
from optparse import make_option
from django.core import exceptions
from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import ugettext as _

from binder.auth import ActiveDirectoryBackend

class Command(BaseCommand):
    """
    option_list = BaseCommand.option_list + (
        make_option('--username', dest='username', default=None,
            help='Specifies the username for the superuser.'),
        make_option('--email', dest='email', default=None,
            help='Specifies the email address for the superuser.'),
        make_option('--noinput', action='store_false', dest='interactive', default=True,
            help=('Tells Django to NOT prompt the user for input of any kind. '
                  'You must use --username and --email with --noinput, and '
                  'superusers created with --noinput will not be able to log '
                  'in until they\'re given a valid password.')),
    )
    """
    
    help = ('Used to import all users from the Active Directory server ' +
        'configured in local_settings.py')

    def handle(self, *args, **options):
        """
        username = options.get('username', None)
        email = options.get('email', None)
        interactive = options.get('interactive')
        verbosity = int(options.get('verbosity', 1))

        # Do quick and dirty validation if --noinput
        if not interactive:
            if not username or not email:
                raise CommandError("You must use --username and --email with --noinput.")
            if not RE_VALID_USERNAME.match(username):
                raise CommandError("Invalid username. Use only letters, digits, and underscores")
            try:
                is_valid_email(email)
            except exceptions.ValidationError:
                raise CommandError("Invalid email address.")
        """
        
        from django.conf import settings
        login = raw_input("Your user name on %s: " % settings.AD_NT4_DOMAIN)
        password = getpass.getpass("Password for %s on %s: " %
            (login, settings.AD_NT4_DOMAIN))
        
        auth = ActiveDirectoryBackend()
        import ldap
        
        try:
            l = auth.get_connection(login, password)
        except ldap.LDAPError as e:
            raise Exception("Login failed: %s" % e)
        
        results = l.search_ext_s(settings.AD_SEARCH_DN, ldap.SCOPE_SUBTREE, 
            "objectClass=user", settings.AD_SEARCH_FIELDS)
        l.unbind_s()
        
        # import pdb; pdb.set_trace()
        
        for result in results:
            # skip referrals? 
            # https://sourceforge.net/tracker/?func=detail&aid=3519430&group_id=2072&atid=102072
            if result[0] is not None:
                try:
                    user = auth.create_or_update_user_from_result(dn=result[0],
                        attrs=result[1], username=result[1]['sAMAccountName'][0])
                    print("Imported user: %s" % user.username)
                except KeyError as e:
                    print("Failed to import user %s: %s" % (result[0], e))
                """
                except TypeError as e:
                    import pdb; pdb.set_trace()
                    print("Failed to import user %s: %s" % (result[0], e))
                """
