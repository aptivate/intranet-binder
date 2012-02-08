# Session tracking with user association and last activity tracking. 

import datetime

from django.conf import settings
from django.contrib.sessions.backends.base import SessionBase, CreateError
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.core.exceptions import SuspiciousOperation
from django.db import IntegrityError, transaction, router, models
from django.utils.encoding import force_unicode

from binder.models import SessionWithIntranetUser

class SessionMiddlewareWithIntranetUser(SessionMiddleware):
    def process_request(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)
        request.session = SessionStore(session_key,
            request)

class SessionStore(SessionBase):
    """
    Implements a database session store which uses IntranetSession
    instead of Session as the model.
    """

    def __init__(self, session_key=None, request=None):
        super(SessionStore, self).__init__(session_key)
        self.request = request

    def load(self):
        # import pdb; pdb.set_trace();
        try:
            s = SessionWithIntranetUser.objects.get(
                session_key = self.session_key,
                expire_date__gt=datetime.datetime.now()
            )
            return self.decode(force_unicode(s.session_data))
        except (Session.DoesNotExist, SuspiciousOperation):
            self.create()
            return {}

    def exists(self, session_key):
        try:
            SessionWithIntranetUser.objects.get(session_key=session_key)
        except Session.DoesNotExist:
            return False
        return True

    def create(self):
        while True:
            self.session_key = self._get_new_session_key()
            try:
                # Save immediately to ensure we have a unique entry in the
                # database.
                self.save(must_create=True)
            except CreateError:
                # Key wasn't unique. Try again.
                continue
            self.modified = True
            self._session_cache = {}
            return

    def save(self, must_create=False):
        # import pdb; pdb.set_trace();
        """
        Saves the current session data to the database. If 'must_create' is
        True, a database error will be raised if the saving operation doesn't
        create a *new* entry (as opposed to possibly updating an existing
        entry).
        """
        obj = SessionWithIntranetUser(
            session_key = self.session_key,
            session_data = self.encode(self._get_session(no_load=must_create)),
            expire_date = self.get_expiry_date(),
        )
        
        if hasattr(self.request, 'user') and self.request.user.is_authenticated():
            obj.user = self.request.user
        else:
            obj.user = None
        
        using = router.db_for_write(SessionWithIntranetUser, instance=obj)
        sid = transaction.savepoint(using=using)
        try:
            obj.save(force_insert=must_create, using=using)
        except IntegrityError:
            if must_create:
                transaction.savepoint_rollback(sid, using=using)
                raise CreateError
            raise

    def delete(self, session_key=None):
        if session_key is None:
            if self._session_key is None:
                return
            session_key = self._session_key
        try:
            SessionWithIntranetUser.objects.get(session_key=session_key).delete()
        except Session.DoesNotExist:
            pass
        