from django.db import models as db_fields
from django.contrib.auth.models import User, UserManager

class ProgramType(db_fields.Model):
    class Meta:
        ordering = ('name',)

    name = db_fields.CharField(max_length=255, unique=True)
    def __unicode__(self):
        return self.name

class Program(db_fields.Model):
    class Meta:
        ordering = ('name',)

    name = db_fields.CharField(max_length=255, unique=True)
    program_type = db_fields.ForeignKey(ProgramType, null=True)
    def __unicode__(self):
        return self.name

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

    full_name = db_fields.CharField(max_length=100)
    job_title = db_fields.CharField(max_length=100)
    sex = db_fields.CharField(max_length=1, choices=SEX_CHOICE)
    program = db_fields.ForeignKey(Program, blank=True, null=True)
    cell_phone = db_fields.CharField(max_length=30)
    office_location = db_fields.CharField(max_length=1, choices=OFFICE_LOCATIONS)
    photo = db_fields.ImageField(upload_to='profile_photos', blank=True, null=True)
    date_left = db_fields.DateField(blank=True, null=True)
    notes = db_fields.TextField(blank=True, verbose_name="Bio")
    
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

    @db_fields.permalink
    def get_absolute_url(self):
        """
        The URL used in search results to link to the "document" found:
        we use this to point to the read-only user profile page.
        """
        return ('admin:binder_intranetuser_readonly', [str(self.id)])
    
    @property
    def is_manager(self):
        return (self.is_superuser or self.groups.filter(name='Manager')) 

from django.contrib.sessions.models import Session

class SessionWithIntranetUser(Session):
    user = db_fields.ForeignKey(User, blank=True, null=True)