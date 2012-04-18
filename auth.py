from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from models import IntranetUser

class IntranetUserBackend(ModelBackend):
    """
    Authenticates against binder.models.IntranetUser
    """
    supports_object_permissions = False
    supports_anonymous_user = True
    supports_inactive_user = True

    # TODO: Model, login attribute name and password attribute name should be
    # configurable.
    def authenticate(self, username=None, password=None):
        try:
            user = IntranetUser.objects.get(username=username)
        except IntranetUser.DoesNotExist:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return None
                
        if user.check_password(password):
            return user

    def get_user(self, user_id):
        try:
            return IntranetUser.objects.get(pk=user_id)
        except IntranetUser.DoesNotExist:
            try:
                return User.objects.get(pk=user_id)
            except User.DoesNotExist:
                return None

from django.conf import settings
import ldap

class ActiveDirectoryBackend:
    """
    Copied from http://djangosnippets.org/snippets/501/
    """
    
    def authenticate(self,username=None,password=None):
        if not self.is_valid(username,password):
            return None
        try:
            user = IntranetUser.objects.get(username=username)
        except User.DoesNotExist:
            l = ldap.initialize(settings.AD_LDAP_URL)
            binddn = "%s@%s" % (username, settings.AD_NT4_DOMAIN)
            l.simple_bind_s(binddn, password)
            result = l.search_ext_s(settings.AD_SEARCH_DN, ldap.SCOPE_SUBTREE, 
                "sAMAccountName=%s" % username,
                settings.AD_SEARCH_FIELDS)[0][1]
            l.unbind_s()

            # givenName == First Name
            if result.has_key('displayName'):
                full_name = result['displayName'][0]
            else:
                full_name = None

            # mail == Email Address
            if result.has_key('mail'):
                email = result['mail'][0]
            else:
                email = None

            user = IntranetUser(username=username,full_name=full_name,email=email)
            user.is_staff = False
            user.is_superuser = False
            user.set_password(password)
            user.save()
        return user

    def get_user(self,user_id):
        try:
            return IntranetUser.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def is_valid (self,username=None,password=None):
        ## Disallowing null or blank string as password
        ## as per comment: http://www.djangosnippets.org/snippets/501/#c868
        if password == None or password == '':
            return False
        binddn = "%s@%s" % (username, settings.AD_NT4_DOMAIN)
        try:
            l = ldap.initialize(settings.AD_LDAP_URL)
            l.simple_bind_s(binddn,password)
            l.unbind_s()
            return True
        except ldap.LDAPError:
            return False