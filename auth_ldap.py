from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from .models import IntranetUser
import ldap

class ActiveDirectoryBackend:
    """
    Copied from http://djangosnippets.org/snippets/501/
    """
    
    def __init__(self):
        from django.contrib.auth.models import Group
        self.default_group = Group.objects.get(name="User")

    def get_connection(self, username, password):
        l = ldap.initialize(settings.AD_LDAP_URL)
        # Disable referrals for AD: http://www.python-ldap.org/faq.shtml
        l.set_option(ldap.OPT_REFERRALS, 0)
        binddn = "%s@%s" % (username, settings.AD_NT4_DOMAIN)
        l.simple_bind_s(binddn, password)
        return l
    
    def authenticate(self,username=None,password=None):
        if not self.is_valid(username,password):
            return None
        
        l = self.get_connection(username, password)
        result = l.search_ext_s(settings.AD_SEARCH_DN, ldap.SCOPE_SUBTREE, 
            "sAMAccountName=%s" % username,
            settings.AD_SEARCH_FIELDS)[0]
        l.unbind_s()
        
        user = self.create_or_update_user_from_result(dn=result[0], 
            attrs=result[1],username=username, password=password)
        
        return user
    
    def create_or_update_user_from_result(self, dn, attrs, username,
        password=None):

        try:
            user = IntranetUser.objects.get(username=username)
        except User.DoesNotExist:
            user = IntranetUser()
        
        try:
            user.username = attrs['sAMAccountName'][0]

            if 'mail' in attrs:
                user.email = attrs['mail'][0]

            if user.full_name is None:
                user.full_name = attrs['displayName'][0]
            
            if 'mobile' in attrs and user.cell_phone is None:
                user.cell_phone = attrs['mobile'][0]
            
            if 'title' in attrs and user.job_title is None:
                user.job_title = attrs['title'][0]
        except KeyError as e:
            raise KeyError("Required attribute %s missing from user %s: %s" %
                (e, dn, attrs))
        
        if user.is_staff is None: 
            user.is_staff = True
        
        if user.is_superuser is None:
            user.is_superuser = False
            
        user.set_password(password)
        user.save()

        if not user.groups.count():
            user.groups.add(self.default_group)
         
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
        try:
            l = self.get_connection(username, password)
            l.unbind_s()
            return True
        except ldap.LDAPError:
            return False
