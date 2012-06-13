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
        response = Client.post(self, path, data, content_type,
            **extra)
        
        if response is None:
            raise Exception("POST method responded with None!")
        
        return self.capture_results('post', response, path, data, content_type,
            **extra)
    
    def capture_results(self, method_name, response, *args, **kwargs):
        # print("%s.%s(%s)" % (self, method_name, args))
        self.last_method = method_name
        self.last_method_args = args
        self.last_method_kwargs = kwargs
        self.last_response = response
        
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
    
    """
    def request(self, **request):
        print "request = %s" % request
        return super(SuperClient, self).request(**request)
    """
    
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
        settings.HAYSTACK_CONNECTIONS[DEFAULT_ALIAS]['SILENTLY_FAIL'] = False
        # settings.HAYSTACK_CONNECTIONS[DEFAULT_ALIAS]['STORAGE'] = 'ram'

        from haystack import connections
        self.search_conn = connections[DEFAULT_ALIAS]
        # self.search_conn.get_backend().use_file_storage = False
        # self.search_conn.get_backend().setup()
        self.search_conn.get_backend().delete_index()
        
        settings.MEDIA_ROOT = '/dev/shm/test_uploads'
        import os
        if os.path.exists(settings.MEDIA_ROOT):
            import shutil
            shutil.rmtree(settings.MEDIA_ROOT)
        os.mkdir(settings.MEDIA_ROOT)
        
        TestCase._pre_setup(self)
        
    def setUp(self):
        TestCase.setUp(self)

        self.unified_index = self.search_conn.get_unified_index()
        self.client = SuperClient()
        
        settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
        
        from django.core.mail.backends.locmem import EmailBackend
        EmailBackend() # create the outbox
        
        from django.core import mail
        self.emails = mail.outbox
        
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
        self.current_user = user
    
    def assertInDict(self, member, container, msg=None):
        """
        Returns the member if the assertion passes.
        
        Makes sense that if you're asserting that a dictionary has a
        member, you might want to use that member! Just saying.
        """
        
        self.assertIn(member, container, msg=msg)
        return container[member]
    
    def absolute_url(self, relative_url):
        """
        Convert a relative URL to an absolute URL, using the name of the
        current site, which is hackish but doesn't require a request object,
        makes the canonical name configurable, and matches what the absurl
        templatetag does.
        """
        
        from django.contrib.sites.models import Site
        return "http://%s%s" % (Site.objects.get_current().domain,
            relative_url)

    def extract_fields(self, form):
        """
        Extract a list of fields names and values from a ModelForm.
        Typical usage:
        
        fields = dict(extract_fields(my_form))
        self.assertEquals("Foo", fields['bar'].verbose_name)
        """
        
        from django.forms.forms import BoundField
        
        for fieldset in form:
            for line in fieldset:
                for field in line:
                    if isinstance(field.field, BoundField):
                        yield field.field.name, field
                    else:
                        yield field.field['name'], field

    def extract_admin_form_field(self, response, field_name):
        """
        Extract a named field from a form generated by the admin interface.
        """
        
        form = self.assertInDict('adminform', response.context)
        fields = dict(self.extract_fields(form))
        return self.assertInDict(field_name, fields)
    
    def value_to_datadict(self, widget, name, value, strict=True):
        """
        There's a value_from_datadict method in each django.forms.widgets widget,
        but nothing that goes in the reverse direction, and
        test_utils.AptivateEnhancedTestCase.update_form_values really wants to
        convert form instance values (Python data) into a set of parameters
        suitable for passing to client.post().
        
        This needs to be implemented for each subclass of Widget that doesn't
        just convert its value to a string.
        """
        
        import django.forms.widgets
        import django.contrib.admin.widgets
        from django.utils.encoding import force_unicode

        if isinstance(widget, django.forms.widgets.FileInput):
            # this is a special case: don't convert FieldFile objects to strings,
            # because the TestClient needs to detect and encode them properly.
            if bool(value):
                return {name: value}
            else:
                # empty file upload, don't set any parameters
                return {}
        
        elif isinstance(widget, django.forms.widgets.MultiWidget):
            values = {}
            for index, subwidget in enumerate(widget.widgets):
                param_name = "%s_%s" % (name, index)
                values.update(self.value_to_datadict(subwidget, param_name,
                    value, strict))
            return values
        
        elif isinstance(widget, django.forms.widgets.CheckboxInput):
            if widget.check_test(value):
                return {name: '1'}
            else:
                # unchecked checkboxes are not sent in HTML
                return {}

        elif isinstance(widget, django.forms.widgets.Select):
            if '__iter__' in dir(value):
                self.assertTrue(len(value) <= 1,
                    "Multiple values of %s are not supported yet (%s)" %
                    (name, value))
                if len(value) == 0:
                    value = None
                elif len(value) == 1:
                    value = value[0]
            
            self.assertNotIn('__iter__', dir(value),
                "Multiple values of %s are not supported yet (%s)" %
                (name, value))
            
            choices = list(widget.choices)
            possible_values = [v for v, label in choices]
            
            if value in possible_values:
                return {name: str(value)}
            elif strict:
                # Since user agent behavior differs, authors should ensure
                # that each menu includes a default pre-selected OPTION
                # (i.e. that a list includes a selected value)
                raise Exception("List without selected value: " +
                    "%s = %s (should be one of: %s)" % (name, value, choices))
            else:
                # most browsers pre-select the first value
                return {name: str(choices[0][0])}
        
        elif isinstance(widget, django.contrib.admin.widgets.RelatedFieldWidgetWrapper):
            subwidget = widget.widget
            subwidget.choices = list(widget.choices)
            return self.value_to_datadict(subwidget, name, value, strict)
            
        elif isinstance(widget, django.forms.widgets.Textarea):
            return {name: force_unicode(value)}
                
        elif getattr(widget, '_format_value', None):
            value = widget._format_value(value)
            if value is None:
                value = ''
            return {name: value}

        else:
            raise Exception("Don't know how to convert data to form values " +
                "for %s" % widget)

    def update_form_values(self, form, **new_values):
        """
        Extract the values from a form, change the ones passed as
        keyword arguments, empty keys whose value is None, delete keys
        which represent a file upload where no file is provided, and
        return a values dict suitable for self.client.post().
        """
        
        params = dict()

        from django.forms.widgets import MultiWidget
        for bound_field in form:
            # fields[k] returns a BoundField, not a django.forms.fields.Field
            # which is where the widget lives
            form_field = bound_field.field
            widget = form_field.widget
            
            # defaults to the current value bound into the form: 
            value = new_values.get(bound_field.name, bound_field.value())
            
            # be strict with values passed by tests to this function,
            # and lax with values that were already in the record/form
            new_params = self.value_to_datadict(widget, bound_field.name, value,
                strict=(bound_field.name in new_values))
            
            params.update(new_params)

        return params

    def extract_error_message(self, response):
        error_message = response.parsed.findtext('.//div[@class="error-message"]')

        if error_message is None:
            error_message = response.parsed.findtext('.//p[@class="errornote"]')
        
        if error_message is not None:
            # extract individual field errors, if any
            more_error_messages = response.parsed.findtext('.//td[@class="errors-cell"]')
            if more_error_messages is not None:
                error_message += more_error_messages
            
            # trim and canonicalise whitespace
            error_message = error_message.strip()
            import re
            error_message = re.sub('\\s+', ' ', error_message)
            
        # return message or None
        return error_message

    def assert_changelist_not_admin_form_with_errors(self, response):
        """
        Checks that the response (to a POST to an admin change form) contains
        a changelist, which means that the update was successful; and not
        an adminform with errors, which would mean that the update was
        unsuccessful.
        
        If not, the update unexpectedly failed, so we extract and report the
        error messages from the form in a helpful way.
        """
        
        self.assertTrue(hasattr(response, 'context'), "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        from django.http import HttpResponseRedirect 
        self.assertNotIsInstance(response, HttpResponseRedirect, 
            "Response is a redirect: did you forget to add follow=True " +
            "to the request?")
        self.assertIsNotNone(response.context, "Empty context in response: " +
            "%s: %s" % (response, dir(response)))

        if 'adminform' in response.context:
            # if there are global errors, this will fail, and show us all
            # the errors when it does.
            self.assertDictEqual({}, response.context['adminform'].form.errors)
            
            # if there are field errors, this will fail, and show us the
            # the field name and the errors
            for fieldset in response.context['adminform']:
                for line in fieldset:
                    # should this be line.errors()?
                    # as FieldlineWithCustomReadOnlyField.errors
                    # is a method, not a property:
                    self.assertIsNone(line.errors,
                        "should not be any errors on %s" % line)
                    for field in line:
                        # similarly django.contrib.admin.helpers.AdminField.errors
                        # is a method:
                        self.assertIsNone(field.errors,
                            "should not be any errors on %s" % field)
            self.assertIsNone(response.context['adminform'].form.non_field_errors)
            self.assertIsNone(self.extract_error_message(response))

        self.assertNotIn('adminform', response.context, "Unexpected " +
            "admin form in response context: %s" % response)
        self.assertIn('cl', response.context, "Missing changelist " +
            "in response context: %s" % response)

    def assert_admin_form_with_errors_not_changelist(self, response,
        expected_field_errors={}, expected_non_field_errors=[]):
        
        """
        Checks that the response (to a POST to an admin change form) contains
        an adminform with errors, which means that the update was
        unsuccessful, and not a changelist, which would mean that the update
        was successful when it should not have been.
        
        Also check that the errors on the adminform are exactly what we
        expected.
        """
        
        from django.http import HttpResponseRedirect 
        self.assertNotIsInstance(response, HttpResponseRedirect,
            ('Unexpected redirect to %s: did the POST succeed when it ' +
            'should have failed? Expected errors were: %s') % 
            (response.get('location', None), expected_field_errors))
        
        self.assertTrue(hasattr(response, 'context'), "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        self.assertIsNotNone(response.context, "Empty context in response: " +
            "%s: %s" % (response, dir(response)))
        self.assertIn('adminform', response.context)
        self.assertDictEqual(expected_field_errors,
            response.context['adminform'].form.errors)
        
        """
        for fieldset in response.context['adminform']:
            for line in fieldset:
                self.assertEqual('', line.errors())
                for field in line:
                    self.assertEqual('', field.errors())
        """
        
        self.assertListEqual(expected_non_field_errors,
            response.context['adminform'].form.non_field_errors())
        self.assertIsNone(self.extract_error_message(response))

        self.assertNotIn('cl', response.context, "Missing changelist " +
            "in response context: %s" % response)
