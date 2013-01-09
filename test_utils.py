import difflib
import pprint

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
        
        from django.template.response import SimpleTemplateResponse
        if isinstance(response, SimpleTemplateResponse):
            response.render()
            
        if getattr(response, 'context', None) is None and \
            getattr(response, 'context_data', None) is not None:
            response.context = response.context_data
        
        if not response.content:
            return response # without setting the parsed attribute

        if response['Content-Type'] != "text/html":
            return response # without setting the parsed attribute
        
        # http://stackoverflow.com/questions/5170252/whats-the-best-way-to-handle-nbsp-like-entities-in-xml-documents-with-lxml
        xml = """<?xml version="1.0" encoding="utf-8"?>\n""" + response.content
        parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
        
        try:
            root = etree.fromstring(xml, parser)
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
                else:
                    lineno = e.lineno
                
            lines = xml.splitlines(True)
            if lineno is not None:
                first_line = max(lineno - 5, 1)
                last_line = min(lineno + 5, len(lines))
                print xml
                print "Context (line %s):\n%s" % (lineno,
                    "".join(lines[first_line:last_line]))
            else:
                print repr(e)
            raise e  
        
        response.parsed = root
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
    
    def additional_login(self, user):
        """
        Simulate another user logging in, without changing our current
        credentials or cookies.
        """
        engine = import_module(settings.SESSION_ENGINE)

        # Create a fake request to store login details.
        request = HttpRequest()
        if self.session:
            request.session = self.session
        else:
            request.session = engine.SessionStore()
        
        request.user = None
        # login() doesn't give our session store a chance to
        # initialise itself for the current request, and django
        # never calls login() during real operation? so it's OK
        # to work around this limitation by poking the request
        # into the session for test purposes?
        request.session.request = request
        self.fake_login_request = request

        login(request, user)

        # Save the session values.
        request.session.save()
        return request
        
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
            request = self.additional_login(user)

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

            return request
        else:
            return None

class AptivateEnhancedTestCase(TestCase):
    longMessage = True
	
    def _pre_setup(self):
        """
        We need to change the Haystack configuration before fixtures are
        loaded, otherwise they end up in the developer's index and not the
        temporary test index, which is bad for both developers and tests.
        
        This is an internal interface and its use is not recommended.
        """

        super(AptivateEnhancedTestCase, self)._pre_setup()

        settings.MEDIA_ROOT = '/dev/shm/test_uploads'
        import os
        if os.path.exists(settings.MEDIA_ROOT):
            import shutil
            shutil.rmtree(settings.MEDIA_ROOT)
        os.mkdir(settings.MEDIA_ROOT)
        
    def setUp(self):
        TestCase.setUp(self)

        self.client = SuperClient()
        
        settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
        
        from django.core.mail.backends.locmem import EmailBackend
        EmailBackend() # create the outbox
        
        from django.core import mail
        self.emails = mail.outbox
        
        from django.template import (Template, NodeList, VariableNode,
            FilterExpression)
        from django.template.debug import DebugVariableNode
        self.addTypeEqualityFunc(Template, self.assertTemplateEqual)
        # self.addTypeEqualityFunc(NodeList, self.assertListEqual)
        self.addTypeEqualityFunc(VariableNode, self.assertVariableNodeEqual)
        self.addTypeEqualityFunc(DebugVariableNode,
            self.assertVariableNodeEqual)
        self.addTypeEqualityFunc(FilterExpression,
            self.assertFilterExpressionEqual)
        
        import warnings
        warnings.filterwarnings('error',
            r"DateTimeField received a naive datetime",
            RuntimeWarning, r'django\.db\.models\.fields')
        
    def assertTemplateEqual(self, first, second, msg=None):
        self.assertListEqual(first.nodelist, second.nodelist, msg)

    def assertVariableNodeEqual(self, first, second, msg=None):
        self.assertEqual(first.filter_expression, second.filter_expression, msg)

    def assertFilterExpressionEqual(self, first, second, msg=None):
        self.assertEqual(first.token, second.token, msg)

    def assertSequenceEqual(self, seq1, seq2,
                            msg=None, seq_type=None, max_diff=80*8):
        """
        Argh! Copied and pasted from case.py to change one line: use
        self.assertEquals instead of ==.
        
        An equality assertion for ordered sequences (like lists and tuples).

        For the purposes of this function, a valid ordered sequence type is one
        which can be indexed, has a length, and has an equality operator.

        Args:
            seq1: The first sequence to compare.
            seq2: The second sequence to compare.
            seq_type: The expected datatype of the sequences, or None if no
                    datatype should be enforced.
            msg: Optional message to use on failure instead of a list of
                    differences.
            max_diff: Maximum size off the diff, larger diffs are not shown
        """
        if seq_type is not None:
            seq_type_name = seq_type.__name__
            if not isinstance(seq1, seq_type):
                raise self.failureException('First sequence is not a %s: %s'
                                            % (seq_type_name, safe_repr(seq1)))
            if not isinstance(seq2, seq_type):
                raise self.failureException('Second sequence is not a %s: %s'
                                            % (seq_type_name, safe_repr(seq2)))
        else:
            seq_type_name = "sequence"

        differing = None
        try:
            len1 = len(seq1)
        except (TypeError, NotImplementedError):
            differing = 'First %s has no length.    Non-sequence?' % (
                    seq_type_name)

        if differing is None:
            try:
                len2 = len(seq2)
            except (TypeError, NotImplementedError):
                differing = 'Second %s has no length.    Non-sequence?' % (
                        seq_type_name)

        if differing is None:
            # here!
            if len1 == len2:
                try:
                    for i in range(len1):
                        self.assertEqual(seq1[i], seq2[i])
                    # all pass
                    return
                except self.failureException:
                    # will be handled below
                    pass
            
            seq1_repr = repr(seq1)
            seq2_repr = repr(seq2)
            if len(seq1_repr) > 30:
                seq1_repr = seq1_repr[:30] + '...'
            if len(seq2_repr) > 30:
                seq2_repr = seq2_repr[:30] + '...'
            elements = (seq_type_name.capitalize(), seq1_repr, seq2_repr)
            differing = '%ss differ: %s != %s\n' % elements

            for i in xrange(min(len1, len2)):
                try:
                    item1 = seq1[i]
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('\nUnable to index element %d of first %s\n' %
                                 (i, seq_type_name))
                    break

                try:
                    item2 = seq2[i]
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('\nUnable to index element %d of second %s\n' %
                                 (i, seq_type_name))
                    break

                if item1 != item2:
                    differing += ('\nFirst differing element %d:\n%s\n%s\n' %
                                 (i, item1, item2))
                    break
            else:
                if (len1 == len2 and seq_type is None and
                    type(seq1) != type(seq2)):
                    # The sequences are the same, but have differing types.
                    return

            if len1 > len2:
                differing += ('\nFirst %s contains %d additional '
                             'elements.\n' % (seq_type_name, len1 - len2))
                try:
                    differing += ('First extra element %d:\n%s\n' %
                                  (len2, seq1[len2]))
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('Unable to index element %d '
                                  'of first %s\n' % (len2, seq_type_name))
            elif len1 < len2:
                differing += ('\nSecond %s contains %d additional '
                             'elements.\n' % (seq_type_name, len2 - len1))
                try:
                    differing += ('First extra element %d:\n%s\n' %
                                  (len1, seq2[len1]))
                except (TypeError, IndexError, NotImplementedError):
                    differing += ('Unable to index element %d '
                                  'of second %s\n' % (len1, seq_type_name))
        standardMsg = differing
        diffMsg = '\n' + '\n'.join(
            difflib.ndiff(pprint.pformat(seq1).splitlines(),
                          pprint.pformat(seq2).splitlines()))

        standardMsg = self._truncateMessage(standardMsg, diffMsg)
        msg = self._formatMessage(msg, standardMsg)
        self.fail(msg)

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
        self.fake_login_request = self.client.login(username=user.username,
            password='johnpassword')
        self.assertTrue(self.fake_login_request, "Login failed")
        self.current_user = user
    
    def assertInDict(self, member, container, msg=None):
        """
        Returns the member if the assertion passes.
        
        Makes sense that if you're asserting that a dictionary has a
        member, you might want to use that member! Just saying. If not,
        you can always throw it away.
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

    def extract_form(self, response):
        """
        Extract the form inserted into the context by generic
        class-based views. Quite trivial, but makes tests more
        readable.
        """
        self.assertIn('context', dir(response), "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        self.assertIsNotNone(response.context, "Empty context in response: " +
            "%s: %s" % (response, dir(response)))
        return self.assertInDict('form', response.context)

    def extract_admin_form(self, response):
        """
        Extract the form generated by the admin interface.
        """

        self.assertIn('context', dir(response), "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        self.assertIsNotNone(response.context, "Empty context in response: " +
            "%s: %s" % (response, dir(response)))
        return self.assertInDict('adminform', response.context)

    def extract_admin_form_fields(self, response):
        """
        Extract all fields from a form generated by the admin interface.
        """
        
        return dict(self.extract_fields(self.extract_admin_form(response)))

    def extract_admin_form_field(self, response, field_name):
        """
        Extract a named field from a form generated by the admin interface.
        """
        
        fields = self.extract_admin_form_fields(response)
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
                values = list(value)
            else:
                values = [value]
            
            choices = list(widget.choices)
            possible_values = [v for v, label in choices]
            found_values = []
            
            for v in values:
                if v in possible_values:
                    found_values.append(str(v))
                elif strict:
                    # Since user agent behavior differs, authors should ensure
                    # that each menu includes a default pre-selected OPTION
                    # (i.e. that a list includes a selected value)
                    raise Exception("List without selected value: " +
                        "%s = %s (should be one of: %s)" % (name, value, choices))
                else:
                    # don't add anything to the list right now
                    pass
            
            if found_values:
                return {name: found_values}
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
        error_message = response.parsed.findtext('.//' +
            self.xhtml('div') + '[@class="error-message"]')

        if error_message is None:
            error_message = response.parsed.findtext('.//' +
                self.xhtml('p') + '[@class="errornote"]')
        
        if error_message is not None:
            # extract individual field errors, if any
            more_error_messages = response.parsed.findtext('.//' +
                self.xhtml('td') + '[@class="errors-cell"]')
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

        if expected_field_errors:
            self.assertEqual(expected_field_errors,
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
        top_error = self.extract_error_message(response)
        import re
        self.assertTrue(re.match('Please correct the error(s)? below.',
            top_error), "Unexpected error message at top of form: %s" %
            top_error)
        self.assertNotIn('cl', response.context, "Unexpected changelist " +
            "in response context: %s" % response)
    
    XHTML_NS = "{http://www.w3.org/1999/xhtml}"
    
    def xhtml(self, name):
        return "%s%s" % (self.XHTML_NS, name) 

    def get_page_element(self, xpath, required=True):
        self.assertTrue(self.client.last_response.content,
            "Last response was empty or not parsed: %s" % 
            self.client.last_response)
        element = self.client.last_response.parsed.find(xpath)
        self.assertIsNotNone(element, "Failed to find %s in page: %s" %
            (xpath, self.client.last_response.content))
        return element

    def assert_search_results_table_get_queryset(self, response):
        try:
            table = response.context['results_table']
        except KeyError as e:
            self.fail("No table in response context: %s" %
                response.context.keys())

        import django_tables2 as tables
        self.assertIsInstance(table, tables.Table)

        columns = table.base_columns.items()
        self.assertNotIn('score', [c[0] for c in columns],
            "Score column is disabled on request")
        
        data = table.data
        from django_tables2.tables import TableData
        self.assertIsInstance(data, TableData)
        
        queryset = data.queryset
        from haystack.query import SearchQuerySet
        self.assertIsInstance(queryset, SearchQuerySet)
        
        return table, queryset

    def assert_not_redirected(self, response, message=None):
        from django.http import HttpResponseRedirect 
        self.assertNotIsInstance(response, HttpResponseRedirect,   
            message)
        self.assertSequenceEqual([],
            getattr(response, 'redirect_chain', []), message)

    def assert_followed_redirect(self, response, expected_url,
        expected_code=200):
        return self.assertFollowedRedirect(response, expected_url,
            expected_code)

    def assertFollowedRedirect(self, response, expected_url,
        expected_code=200):

        expected_uri = response.real_request.build_absolute_uri(expected_url)

        message = "Response was not a redirect to %s: " % expected_uri
        message += "(there should be a redirect chain"
        if response.status_code in (301, 302):
            message += ": did you forget to pass follow=True to " + \
                "client.get()?"
        message += ") " + response.content
         
    	attrs = self.assertInDict('redirect_chain', dir(response),
    	    message)
    	
        expected_uri = response.real_request.build_absolute_uri(expected_url)
        self.assertSequenceEqual([(expected_uri, 302)],
            response.redirect_chain, message)
        self.assertEquals(expected_code, response.status_code,
            "final response, after following, should have been a " +
            "%s, not this: %s" % (expected_code, response.content))

    def admin_change_url(self, instance):
        # Return the URL needed to call the admin change form
        # for the given instance
        from django.core.urlresolvers import reverse
        return reverse('admin:%s_%s_change' %
            (instance._meta.app_label, instance._meta.module_name),
            args=[instance.pk])

    def assert_login_required(self, view, message=None):
        from django.core.urlresolvers import reverse
        uri = reverse(view)
        response = self.client.get(uri)
        
        from django.conf import settings
        login_url = settings.LOGIN_URL + "?next=" + uri
        self.assertRedirects(response, login_url)
        
        return response

