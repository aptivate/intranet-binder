from django.db.models.base import Model
from django.db.models import fields, related, permalink
from django.db.models.fields import files

from django.contrib.auth.models import Group
class IntranetGroup(Group):
    """
    We need a custom Group class to identify the Group(s) of Administrators,
    who get superuser permissions if they are a member of any of these groups.
    
    We deliberately don't update the is_superuser flag of all users in this
    group whenever the administrators flag changes. That would be extremely
    dangerous: too easy to make all users superusers or wipe out all
    superusers in one go. So changing this flag only affects whether future
    changes to a user's group result in them becoming a superuser or not.
    """
    administrators = fields.BooleanField(help_text="""
        If enabled, all members of this group automatically become system
        administrators (super users) regardless of what permissions are
        assigned to the group""")
    
    @property
    def group(self):
        return Group.objects.get(pk=self.pk) 

class ProgramType(Model):
    class Meta:
        ordering = ('name',)

    name = fields.CharField(max_length=255, unique=True)
    def __unicode__(self):
        return self.name

class Program(Model):
    class Meta:
        ordering = ('name',)

    name = fields.CharField(max_length=255, unique=True)
    program_type = related.ForeignKey(ProgramType, null=True)
    def __unicode__(self):
        return self.name

from django.contrib.auth.models import User, UserManager
from django.db.models.signals import m2m_changed
from django.dispatch import receiver

class IntranetUser(User):
    objects = UserManager()

    class Meta:
        ordering = ('username',)
        
    SEX_CHOICE = (
        ('M', 'Male'),
        ('F', 'Female'),
    )
    
    OFFICE_LOCATIONS = (
        ('7', '7th Floor'),
        ('8', '8th Floor'),
        ('9', '9th Floor'),
    )

    full_name = fields.CharField(max_length=100)
    job_title = fields.CharField(max_length=100)
    sex = fields.CharField(max_length=1, choices=SEX_CHOICE)
    program = related.ForeignKey(Program, blank=True, null=True)
    cell_phone = fields.CharField(max_length=30)
    office_location = fields.CharField(max_length=1, choices=OFFICE_LOCATIONS)
    photo = files.ImageField(upload_to='profile_photos', blank=True, null=True)
    date_joined_nondjango = fields.DateField(blank=True, null=True,
        verbose_name="Date joined")
    date_left = fields.DateField(blank=True, null=True)
    notes = fields.TextField(blank=True, verbose_name="Bio")
    
    def get_full_name(self):
        return self.full_name

    """
    def hash_password(self, raw_password):
        if raw_password is None:
            return None
        else:
            import random
            algo = 'sha1'
            salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
            hsh = get_hexdigest(algo, salt, raw_password)
            return '%s$%s$%s' % (algo, salt, hsh)

    def set_password(self, raw_password):
        if raw_password is None:
            self.set_unusable_password()
        else:
            self.password = self.hash_password(raw_password)
    """

    def get_userlevel(self):
        groups = self.groups.all()
        if groups:
            return groups[0]
        else:
            return None
    get_userlevel.short_description = 'User Level'

    def is_logged_in(self):
        import datetime
        n = SessionWithIntranetUser.objects.filter(user=self,
            expire_date__gt=datetime.datetime.now()).count()
        # print "sessions for %s = %s" % (self, n)
        return (n > 0)

    @permalink
    def get_absolute_url(self):
        """
        The URL used in search results to link to the "document" found:
        we use this to point to the read-only user profile page.
        """
        return ('admin:binder_intranetuser_readonly', [str(self.id)])
    
    @property
    def is_manager(self):
        groups = IntranetGroup.objects.filter(administrators=True,
            user__pk=self.id)
        return (self.is_superuser or len(groups) > 0)

    def save(self, force_insert=False, force_update=False, using=None):
        self.is_active = True
        self.is_staff = True
        return super(IntranetUser, self).save(force_insert, force_update, using)
    
    @staticmethod
    def groups_changed(sender, **kwargs):
        """
        If the user is in an administrators group, then they should be made
        a superuser, otherwise they should not be a superuser.
        
        We can't do this by overriding save(), because the model admin
        hasn't applied the changes to the groups in the database at that
        time, so we won't see or know about the user's new group memberships.
        """
        
        # import pdb; pdb.set_trace()
        
        new_superuser_value = False
        user = kwargs['instance']
            
        for group in user.groups.all():
            try:
                if group.intranetgroup.administrators:
                    new_superuser_value = True
                    break
            except IntranetGroup.DoesNotExist:
                # might be a plain group, in which case it can't be a 
                # group of administrators
                pass
        
        if new_superuser_value != user.is_superuser:
            user.is_superuser = new_superuser_value
            user.save()
    
    def reload(self):
        return self.__class__.objects.get(pk=self.pk)

@receiver(m2m_changed, sender=User.groups.through,
    dispatch_uid="User_groups_changed")
def User_groups_changed(sender, **kwargs):
    IntranetUser.groups_changed(sender, **kwargs)

from django.contrib.sessions.models import Session

class SessionWithIntranetUser(Session):
    user = related.ForeignKey(User, blank=True, null=True)