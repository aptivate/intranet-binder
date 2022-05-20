import difflib
import pprint
import datetime

from lxml import etree

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpRequest
from django.http.request import QueryDict
from django.test import TestCase
from django.test.client import Client, ClientHandler, encode_multipart, \
    MULTIPART_CONTENT, BOUNDARY
from importlib import import_module
from django.utils import timezone


class SuperClientHandler(ClientHandler):
    def get_response(self, request):
        request.body  # access it now to stop later access from blowing up
        # after cms.utils.get_language_from_request() forces discarding it.

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
            auto_parse_response_as_xhtml=True, **extra):
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
            auto_parse_response_as_xhtml=auto_parse_response_as_xhtml, **extra)

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
            return response  # without setting the parsed attribute

        if not kwargs.get('auto_parse_response_as_xhtml', True):
            return response  # without setting the parsed attribute

        mime_type, _, charset = response['Content-Type'].partition(';')
        if mime_type != "text/html":
            return response  # without setting the parsed attribute

        if not response.content:
            raise Exception("Response is HTML but unexpectedly has no "
                "content: %s: %s" % (response.status_code, response.content))

        # http://stackoverflow.com/questions/5170252/whats-the-best-way-to-handle-nbsp-like-entities-in-xml-documents-with-lxml
        xml = """<?xml version="1.0" encoding="utf-8"?>\n""" + response.content
        parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False)

        try:
            root = etree.fromstring(xml, parser)
        except SyntaxError as e:
            import re
            match = re.match((
                r'Opening and ending tag mismatch: '
                r'(\w+) line (\d+) and (\w+), line (\d+), column (\d+)'),
                str(e)
            )
            if match:
                lineno = int(match.group(2))
            else:
                match = re.match(r'.*, line (\d+), column (\d+)', str(e))
                if match:
                    lineno = int(match.group(1))
                else:
                    lineno = e.lineno

            lines = xml.splitlines(True)
            if lineno is not None:
                first_line = max(lineno - 5, 1)
                last_line = min(lineno + 5, len(lines))
                print(xml)
                print(("Context (line %s):\n>>%s<<" % (lineno,
                    "".join(lines[first_line:last_line]))))
            else:
                print((repr(e)))

            raise

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

from django.forms import BoundField


class FormUtilsMixin(object):

    def extract_fields(self, form):
        """
        Extract a list of fields names and values from a ModelForm.
        Typical usage:

        fields = dict(extract_fields(my_form))
        self.assertEquals("Foo", fields['bar'].verbose_name)
        """
        for fieldset in form:
            for line in fieldset:
                for field in line:
                    if isinstance(field.field, BoundField):
                        yield field.field.name, field
                    else:
                        yield field.field['name'], field

    def extract_field(self, form, field_name):
        for fieldset in form:
            for line in fieldset:
                for field in line:
                    if isinstance(field.field, BoundField):
                        if field.field.name == field_name:
                            return field
                    else:
                        if field.field['name'] == field_name:
                            return field
        raise KeyError('Field not found in form: %s' % field_name)

    def extract_form(self, response, message=None):
        """
        Extract the form inserted into the context by generic
        class-based views. Quite trivial, but makes tests more
        readable.
        """

        if message is None:
            prefix = ''
        else:
            prefix = '%s: ' % message

        self.assertIn('context', dir(response), prefix + "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        self.assertIsNotNone(response.context, prefix + "Empty context in " +
            "response: %s: %s" % (response, dir(response)))
        return self.assertInDict('form', response.context, prefix +
            "Missing form in response context")

    def extract_admin_form(self, response):
        """
        Extract the form generated by the admin interface.
        """

        self.assertIn('context', dir(response), "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        self.assertIsNotNone(response.context, "Empty context in response: " +
            "%s: %s" % (response, dir(response)))
        return self.assertInDict('adminform', response.context,
            response.content)

    def extract_admin_form_as_normal_form(self, response):
        form = self.extract_admin_form(response)

        flat_form = []
        for fieldset in form:
            for line in fieldset:
                for field in line:
                    flat_form.append(field.field)

        return flat_form

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

    def extract_values_from_choices(self, choices):
        # allow for the optgroup syntax
        possible_values = []
        for option_value, option_label in choices:
            if isinstance(option_label, (list, tuple)):
                possible_values += [v for v, label in option_label]
            else:
                possible_values.append(option_value)
        return possible_values

    def extract_labels_from_choices(self, choices):
        # allow for the optgroup syntax
        possible_values = []
        for option_value, option_label in choices:
            if isinstance(option_label, (list, tuple)):
                possible_values += [label for v, label in option_label]
            else:
                possible_values.append(option_label)
        return possible_values

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
        import django.contrib.auth.forms
        from django.utils.encoding import force_text

        try:
            from captcha.widgets import ReCaptcha
        except ImportError:
            ReCaptcha = None

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
            if isinstance(value, (list, tuple)):
                values = list(value)
            else:
                values = [value]

            choices = list(widget.choices)
            possible_values = self.extract_values_from_choices(choices)
            found_values = []

            for v in values:
                if v in possible_values:
                    found_values.append(str(v))
                elif v == '' and isinstance(widget, django.forms.widgets.RadioSelect):
                    # It's possible not to select any option in a RadioSelect
                    # widget, although this will probably generate an error
                    # as the field is probably required, but we need to be
                    # able to test that behaviour, by passing an empty string.
                    #
                    # In that case, we don't add anything to the POST data,
                    # because a user agent wouldn't either if the user hasn't
                    # selected any of the radio buttons
                    pass
                elif strict:
                    # Since user agent behaviour differs, authors should ensure
                    # that each menu includes a default pre-selected OPTION
                    # (i.e. that a list includes a selected value)
                    raise Exception("List without selected value: "
                        "%s = %s (should be one of: %s)" %
                        (name, value, self.extract_labels_from_choices(choices)))
                else:
                    # don't add anything to the list right now
                    pass

            if found_values:
                return {name: found_values}
            elif isinstance(widget, django.forms.widgets.RadioSelect):
                # As above, it's possible not to select any option in a
                # RadioSelect widget. In that case, we don't add anything
                # to the POST data.
                return {}
            elif len(possible_values) == 0:
                # it's possible to select no option in a drop-down list with
                # no options!
                return {}
            else:
                # most browsers pre-select the first value
                return {name: str(possible_values[0])}

        elif isinstance(widget, django.contrib.admin.widgets.RelatedFieldWidgetWrapper):
            subwidget = widget.widget
            subwidget.choices = list(widget.choices)
            return self.value_to_datadict(subwidget, name, value, strict)

        elif isinstance(widget, django.forms.widgets.Textarea):
            return {name: force_text(value)}

        elif isinstance(widget, django.contrib.auth.forms.ReadOnlyPasswordHashWidget):
            return {}

        elif isinstance(widget, ReCaptcha):
            raise Exception("You can't spoof a ReCaptcha, delete it from "
                "form.fields instead!")

        elif getattr(widget, 'format_value', None):
            value = widget.format_value(value)
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

        if new_values is None:
            new_values = {}

        field_names = [bound_field.name for bound_field in form]
        for name in new_values:
            if name not in field_names:
                self.fail("Tried to change value for unknown field %s. Valid "
                    "field names are: %s" % (name, field_names))

        for bound_field in form:
            # fields[k] returns a BoundField, not a django.forms.fields.Field
            # which is where the widget lives
            form_field = bound_field.field
            widget = form_field.widget

            # defaults to the current value bound into the form:
            value = new_values.get(bound_field.html_name, bound_field.value())

            # be strict with values passed by tests to this function,
            # and lax with values that were already in the record/form
            new_params = self.value_to_datadict(
                widget, bound_field.html_name,
                value,
                strict=(bound_field.name in new_values)
            )

            params.update(new_params)

        return params

    def fill_form_with_dummy_data(self, form, post_data=None):
        import django.forms.fields
        import django.forms.widgets

        try:
            from captcha.widgets import ReCaptcha
        except ImportError:
            ReCaptcha = None

        if post_data is None:
            post_data = {}
        else:
            post_data = dict(post_data)

        fields_to_delete = []

        for field in form:
            if field.field.required and not post_data.get(field.name):
                widget = field.field.widget

                if isinstance(widget, django.forms.widgets.Select):
                    choices = list(widget.choices)
                    if not choices:
                        choices = list(field.field.choices)
                    possible_values = [v for v, label in choices]
                    if isinstance(widget, django.forms.widgets.SelectMultiple):
                        value = [possible_values[0]]
                    else:
                        value = possible_values[0]

                elif isinstance(field.field, django.forms.fields.EmailField):
                    value = "whee@example.com"

                elif isinstance(widget, ReCaptcha):
                    fields_to_delete.append(field.name)
                    continue

                else:
                    value = "Whee"

                post_data[field.name] = value

        query_dict = QueryDict('', mutable=True).copy()
        for key, value in list(post_data.items()):
            if isinstance(value, (list, tuple)):
                query_dict.setlist(key, value)
            else:
                query_dict.setlist(key, [value])
        query_dict._mutable = False

        new_form = form.__class__(query_dict)

        for field_name in fields_to_delete:
            del new_form.fields[field_name]

        # post_data is not very useful if fields_to_delete is not empty,
        # because any form constructed with it won't validate, but it is
        # useful under some circumstances, so return it anyway.
        """
        if fields_to_delete:
            post_data = None
        """

        return new_form, post_data

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
            expected_field_errors=None, expected_non_field_errors=None):
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

        if expected_field_errors is not None:
            self.assertDictEqual(expected_field_errors,
                response.context['adminform'].form.errors)

        """
        for fieldset in response.context['adminform']:
            for line in fieldset:
                self.assertEqual('', line.errors())
                for field in line:
                    self.assertEqual('', field.errors())
        """

        if expected_non_field_errors is not None:
            self.assertListEqual(expected_non_field_errors,
                response.context['adminform'].form.non_field_errors())
        top_error = self.extract_error_message(response)

        if not expected_field_errors and not expected_non_field_errors:
            self.assertIsNone(top_error)
        else:
            self.assertIsNotNone(top_error)
            import re
            self.assertTrue(re.match('Please correct the error(s)? below.',
                top_error), "Unexpected error message at top of form: %s" %
                top_error)
            self.assertNotIn('cl', response.context, "Unexpected changelist " +
                "in response context: %s" % response)


class AptivateEnhancedTestCase(FormUtilsMixin, TestCase):
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
        EmailBackend()  # create the outbox

        from django.core import mail
        self.emails = mail.outbox

        from django.template import Template, VariableNode, FilterExpression
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

        from django.contrib.auth.hashers import make_password
        self.test_password = 'testpass'
        self.test_password_encrypted = make_password(self.test_password)

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
        from unittest.util import safe_repr
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

            for i in range(min(len1, len2)):
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
        credentials = dict(username=user.username,
            password=self.test_password)
        self.assertIn('django.contrib.sessions', settings.INSTALLED_APPS,
            "This method currently doesn't work if the " +
            "django.contrib.sessions app is not enabled")
        user_authenticated = authenticate(**credentials)
        self.assertIsNotNone(user_authenticated, "authentication failed " +
            "for %s" % credentials)
        self.assertTrue(user_authenticated.is_active, "cannot log in as " +
            "inactive user %s" % user)

        self.fake_login_request = self.client.login(**credentials)
        self.assertTrue(self.fake_login_request, "Login failed")
        self.current_user = user

    def assertInDict(self, member, container, msg=None):
        """
        Returns the member if the assertion passes.

        Makes sense that if you're asserting that a dictionary has a
        member, you might want to use that member! Just saying. If not,
        you can always throw it away.
        """

        if isinstance(container, dict):
            self.assertIsInstance(member, str, "Dict keys must be strings")
        elif isinstance(container, str):
            self.assertIsInstance(member, str, "Only strings can be in other strings")
        self.assertIn(member, container, msg=msg)

        try:
            return container[member]
        except TypeError as e:
            raise TypeError(("%s (is the second argument really a " +
                "dictionary? %s)") % (e, container))

    def absolute_url_for_site(self, relative_url):
        """
        Convert a relative URL to an absolute URL, using the name of the
        current site, which is hackish but doesn't require a request object
        (so it can be generated in an email, for example), makes the
        canonical name configurable, and matches what the absurl
        templatetag does.
        """

        from django.contrib.sites.models import Site
        return "http://%s%s" % (Site.objects.get_current().domain,
            relative_url)

    def absolute_url_for_request(self, relative_url):
        """
        Convert a relative URL to an absolute URL, using the server name
        hard-coded in django.test.client.RequestFactory, which matches the
        value used by HttpRequest.build_absolute_uri when called by
        the test client.
        """
        return "http://%s%s" % ('testserver', relative_url)

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
        except KeyError:
            self.fail("No table in response context: %s" %
                list(response.context.keys()))

        import django_tables2 as tables
        self.assertIsInstance(table, tables.Table)

        columns = list(table.base_columns.items())
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
            expected_code=200, error_message_path=None):
        return self.assertFollowedRedirect(response, expected_url,
            expected_code, error_message_path)

    def assertFollowedRedirect(self, response, expected_url,
            expected_code=200, error_message_path=None):

        expected_uri = response.real_request.build_absolute_uri(expected_url)

        self.assertNotIn(int(response.status_code), (301, 302),
            "Response was a redirect, but was not followed. " +
            "Please add follow=True to the request call")

        message = "Response was not a redirect to %s: " % expected_uri
        message += "(there should be a redirect chain)\n\n"

        """
        elif error_message_path:
            error_message_path = './/' + error_message_path
            error_message = response.parsed.findtext(error_message_path)
            if error_message:
                message += ": " + error_message
            else:
                message += (", and failed to find an error message matching %s"
                    % error_message_path)
        """

        message += "The complete response (status %s) was: %s" % \
            (response.status_code, response.content)

        redirect_chain = self.assertInDict(
            'redirect_chain', response.__dict__, message)

        self.assert_no_form_with_errors(response)

        expected_uri = response.real_request.build_absolute_uri(expected_url)
        self.assertSequenceEqual([(expected_uri, 302)],
            redirect_chain, message)
        self.assertEqual(expected_code, response.status_code,
            "final response, after following, should have been a " +
            "%s, not this: %s" % (expected_code, response.content))

    def assertRedirectedWithoutFollowing(self, response, expected_url,
            status_code=302, host=None, msg_prefix=''):
        """Asserts that a response redirected to a specific URL. Unlike
        :method:assertRedirects, this one will work for external links,
        since it doesn't try to follow them.
        """
        if msg_prefix:
            msg_prefix += ": "

        self.assertFalse(hasattr(response, 'redirect_chain'),
            "A redirect was followed, it's too late to call "
            "assertRedirectedWithoutFollowing")

        # Not a followed redirect
        self.assertEqual(response.status_code, status_code,
            msg_prefix + "Response didn't redirect as expected: Response"
            " code was %d (expected %d)" %
                (response.status_code, status_code))

        try:
            from urllib.parse import urlsplit, urlunsplit
        except ImportError:     # Python 2
            from urllib.parse import urlsplit, urlunsplit

        e_scheme, e_netloc, e_path, e_query, e_fragment = urlsplit(expected_url)
        if not (e_scheme or e_netloc):
            expected_url = urlunsplit(('http', host or 'testserver', e_path,
                e_query, e_fragment))

        actual_url = response['Location']
        self.assertEqual(actual_url, expected_url,
            msg_prefix + "Response redirected to '%s', expected '%s'" %
                (actual_url, expected_url))

    def assert_no_form_with_errors(self, response, form_name='form'):
        if response.status_code == 200:
            # most likely this was a form validation error, so see if
            # we can find it and report it.
            if form_name in response.context:
                form = response.context[form_name]
                self.assertDictEqual({}, form.errors, "Found an unexpected "
                    "validation error in response to form submission")

    def admin_change_url(self, instance):
        # Return the URL needed to call the admin change form
        # for the given instance
        from django.urls import reverse
        return reverse('admin:%s_%s_change' %
            (instance._meta.app_label, instance._meta.module_name),
            args=[instance.pk])

    def admin_changelist_url(self, model):
        # Return the URL needed to call the admin changelist page
        # for the given model
        from django.urls import reverse
        return reverse('admin:%s_%s_changelist' %
            (model._meta.app_label, model._meta.module_name))

    def assert_login_required(self, view, message=None):
        from django.urls import reverse
        uri = reverse(view)
        response = self.client.get(uri)

        from django.conf import settings
        login_url = settings.LOGIN_URL + "?next=" + uri
        self.assertRedirects(response, login_url)

        return response


def throwing_exception_on_HttpResponseForbidden(decoratee_method):
    """
    This test decorator makes debugging tests easier by throwing an exception
    whenever a HttpResponseForbidden response is constructed, instead of
    returning it as an HttpResponse with status 403.
    """

    def decorated_method(*args, **kwargs):
        # Extract the context hidden away by instrumented_test_render
        extracted_data = {}

        def after_store_rendered_templates_extract_stored_data(store, *args,
                **kwargs):
            extracted_data.update(store)

        from aptivate_monkeypatch.monkeypatch import after
        import django.test.client

        with after(django.test.client, 'store_rendered_templates',
                after_store_rendered_templates_extract_stored_data):

            def after_construction_throw_exception_with_reason_from_context(self,
                    content, *args, **kwargs):

                raise Exception(extracted_data['context']['reason'])

            from aptivate_monkeypatch.monkeypatch import modify_return_value
            from django.http import HttpResponseForbidden

            with modify_return_value(HttpResponseForbidden, '__init__',
                    after_construction_throw_exception_with_reason_from_context):

                return decoratee_method(*args, **kwargs)

    decorated_method.__name__ = decoratee_method.__name__
    return decorated_method


class MonotonicTimeMixin(object):

    def setUp(self):
        # Ensure value of "now" always increases by amount sufficient
        # to show up as a change, even if db resolution for datetime
        # is one second.
        # timezone.now is used within save()
        def now_iter(start):
            t = start
            while True:
                t += datetime.timedelta(minutes=1)
                yield t

        from unittest.mock import patch
        with patch.object(timezone, 'now', return_value=now_iter(timezone.now())):
            super(MonotonicTimeMixin, self).setUp()
