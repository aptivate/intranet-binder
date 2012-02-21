from lxml import etree

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpRequest
from django.test import TestCase
from django.test.client import Client, ClientHandler, encode_multipart, \
    MULTIPART_CONTENT, BOUNDARY
from django.utils.importlib import import_module

class SuperClientHandler(ClientHandler):
    def get_response(self, request):
        response = super(SuperClientHandler, self).get_response(request)
        response.real_request = request
        return response

class SuperClient(Client):
    def __init__(self, enforce_csrf_checks=False, **defaults):
        super(SuperClient, self).__init__(enforce_csrf_checks, **defaults)
        self.handler = SuperClientHandler(enforce_csrf_checks)
        
    def get(self, *args, **extra):
        response = Client.get(self, *args, **extra)
        return self.capture_results('get', response, *args, **extra)

    def post(self, path, data={}, content_type=MULTIPART_CONTENT,
             **extra):
        """
        Pickle the request first, in case it contains a StringIO (file upload)
        that can't be read twice.
        
        If the data doesn't have an items() method, then it's probably already
        been converted to a string (encoded), and if we try again we'll call
        the nonexistent items() method and fail, so just don't encode it at
        all."""
        if content_type == MULTIPART_CONTENT and \
            getattr(data, 'items', None) is not None:
            data = encode_multipart(BOUNDARY, data)
        
        # print "session cookie = %s" % (
        # self.cookies[django_settings.SESSION_COOKIE_NAME])
        response = Client.post(self, path, data, content_type, **extra)
        
        if response is None:
            raise Exception("POST method responded with None!")
        
        return self.capture_results('post', response, path, data,
            content_type, **extra)
    
    def capture_results(self, method_name, response, *args, **kwargs):
        # print("%s.%s(%s)" % (self, method_name, args))
        self.last_method = method_name
        self.last_method_args = args
        self.last_method_kwargs = kwargs
        
        if not response.content:
            return response # without setting the parsed attribute
        
        # http://stackoverflow.com/questions/5170252/whats-the-best-way-to-handle-nbsp-like-entities-in-xml-documents-with-lxml
        x = """<?xml version="1.0" encoding="utf-8"?>\n""" + response.content
        p = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
        
        try:
            r = etree.fromstring(x, p)
        except SyntaxError as e:
            import re
            match = re.match('Opening and ending tag mismatch: ' +
                '(\w+) line (\d+) and (\w+), line (\d+), column (\d+)', str(e))
            if match:
                lineno = int(match.group(2))
            else:
                match = re.match('.*, line (\d+), column (\d+)', str(e))
                if match:
                    lineno = int(match.group(1))

            if not match:            
                lineno = e.lineno
                
            lines = x.splitlines(True)
            if lineno is not None:
                first_line = max(lineno - 5, 1)
                last_line = min(lineno + 5, len(lines))
                print x
                print "Context (line %s):\n%s" % (lineno,
                    "".join(lines[first_line:last_line]))
            else:
                print repr(e)
            raise e  
        
        setattr(response, 'parsed', r)
        return response
        
    def retry(self):
        """Try the same request again (e.g. after login)."""
        # print "retry kwargs = %s" % self.last_method_kwargs 
        return getattr(self, self.last_method)(*self.last_method_args,
            **self.last_method_kwargs)
    
    def request(self, **request):
        # print "request = %s" % request
        return super(SuperClient, self).request(**request)

    def login(self, **credentials):
        """
        Sets the Factory to appear as if it has successfully logged into a site.

        Returns True if login is possible; False if the provided credentials
        are incorrect, or the user is inactive, or if the sessions framework is
        not available.

        Work around the limitation in django.test.Client that it always
        constructs the session with just the cookie name, not using our
        Middleware, so we don't get to capture the request and hence neither
        the current user.
        """
        user = authenticate(**credentials)
        if user and user.is_active \
                and 'django.contrib.sessions' in settings.INSTALLED_APPS:
            engine = import_module(settings.SESSION_ENGINE)

            # Create a fake request to store login details.
            request = HttpRequest()
            if self.session:
                request.session = self.session
            else:
                request.session = engine.SessionStore()

            class FakeRequest(object):
                def __init__(self, user):
                    self.user = user
            request.session.request = FakeRequest(user)

            login(request, user)

            # Save the session values.
            request.session.save()

            # Set the cookie to represent the session.
            session_cookie = settings.SESSION_COOKIE_NAME
            self.cookies[session_cookie] = request.session.session_key
            cookie_data = {
                'max-age': None,
                'path': '/',
                'domain': settings.SESSION_COOKIE_DOMAIN,
                'secure': settings.SESSION_COOKIE_SECURE or None,
                'expires': None,
            }
            self.cookies[session_cookie].update(cookie_data)

            return True
        else:
            return False

class AptivateEnhancedTestCase(TestCase):
    def _pre_setup(self):
        """
        We need to change the Haystack configuration before fixtures are
        loaded, otherwise they end up in the developer's index and not the
        temporary test index, which is bad for both developers and tests.
        
        This is an internal interface and its use is not recommended.
        """

        from haystack.constants import DEFAULT_ALIAS
        settings.HAYSTACK_CONNECTIONS[DEFAULT_ALIAS]['PATH'] = '/dev/shm/whoosh'
        # settings.HAYSTACK_CONNECTIONS[DEFAULT_ALIAS]['STORAGE'] = 'ram'

        from haystack import connections
        self.search_conn = connections[DEFAULT_ALIAS]
        # self.search_conn.get_backend().use_file_storage = False
        # self.search_conn.get_backend().setup()
        self.search_conn.get_backend().delete_index()
        
        TestCase._pre_setup(self)
        
    def setUp(self):
        TestCase.setUp(self)

        self.unified_index = self.search_conn.get_unified_index()
        self.client = SuperClient()
        
    def assign_fixture_to_filefield(self, fixture_file_name, filefield):
        import sys
        module = sys.modules[self.__class__.__module__]

        import os.path
        path = os.path.join(os.path.dirname(module.__file__), 'fixtures',
            fixture_file_name)
        
        from django.core.files import File as DjangoFile
        df = DjangoFile(open(path))
        filefield.save(fixture_file_name, df, save=False) 

    def login(self, user):
        self.assertTrue(self.client.login(username=user.username,
            password='johnpassword'), "Login failed")
        