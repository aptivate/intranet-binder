from monkeypatch import before, after, patch

# import os
# os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from django.test.client import ClientHandler
def get_response_with_exception_passthru(original_function, self, request):
    """
    Returns an HttpResponse object for the given HttpRequest. Unlike
    the original get_response, this does not catch exceptions, which
    allows you to see the full stack trace in your tests instead of
    a 500 error page.
    """
    
    # print("get_response(%s)" % request)
    
    from django.core import exceptions, urlresolvers
    from django.conf import settings

    # Setup default url resolver for this thread, this code is outside
    # the try/except so we don't get a spurious "unbound local
    # variable" exception in the event an exception is raised before
    # resolver is set
    urlconf = settings.ROOT_URLCONF
    urlresolvers.set_urlconf(urlconf)
    resolver = urlresolvers.RegexURLResolver(r'^/', urlconf)
    response = None
    # Apply request middleware
    for middleware_method in self._request_middleware:
        response = middleware_method(request)
        if response:
            break

    if response is None:
        if hasattr(request, "urlconf"):
            # Reset url resolver with a custom urlconf.
            urlconf = request.urlconf
            urlresolvers.set_urlconf(urlconf)
            resolver = urlresolvers.RegexURLResolver(r'^/', urlconf)

        callback, callback_args, callback_kwargs = resolver.resolve(
                request.path_info)

        # Apply view middleware
        for middleware_method in self._view_middleware:
            response = middleware_method(request, callback, callback_args, callback_kwargs)
            if response:
                break

    if response is None:
        try:
            response = callback(request, *callback_args, **callback_kwargs)
        except Exception, e:
            # If the view raised an exception, run it through exception
            # middleware, and if the exception middleware returns a
            # response, use that. Otherwise, reraise the exception.
            for middleware_method in self._exception_middleware:
                response = middleware_method(request, e)
                if response:
                    break
            if response is None:
                raise

    # Complain if the view returned None (a common error).
    if response is None:
        try:
            view_name = callback.func_name # If it's a function
        except AttributeError:
            view_name = callback.__class__.__name__ + '.__call__' # If it's a class
        raise ValueError("The view %s.%s didn't return an HttpResponse object." % (callback.__module__, view_name))

    # If the response supports deferred rendering, apply template
    # response middleware and the render the response
    if hasattr(response, 'render') and callable(response.render):
        for middleware_method in self._template_response_middleware:
            response = middleware_method(request, response)
        response.render()

    # Reset URLconf for this thread on the way out for complete
    # isolation of request.urlconf
    urlresolvers.set_urlconf(None)

    # Apply response middleware, regardless of the response
    for middleware_method in self._response_middleware:
        response = middleware_method(request, response)
    response = self.apply_response_fixes(request, response)

    return response
patch(ClientHandler, 'get_response', get_response_with_exception_passthru) 

def dont_apply_response_fixes(original_function, self, request, response):
    """
    It doesn't make any sense to rewrite location headers in tests,
    because the test client doesn't know or care what hostname is
    used in a request, so it could change in future without breaking
    most people's tests, EXCEPT tests for redirect URLs!
    """
    return response
# patch(ClientHandler, 'apply_response_fixes', dont_apply_response_fixes)

from django.db.models.query import QuerySet
def queryset_get_with_exception_detail(original_function, self, *args, **kwargs):
    """
    Performs the query and returns a single object matching the given
    keyword arguments. This version provides extra details about the query
    if it fails to find any results.
    """
    
    clone = self.filter(*args, **kwargs)
    if self.query.can_filter():
        clone = clone.order_by()
    num = len(clone)
    if num == 1:
        return clone._result_cache[0]
    if not num:
        raise self.model.DoesNotExist(("%s matching query does not exist " +
            "(query was: %s, %s)") % (self.model._meta.object_name,
                args, kwargs))
    raise self.model.MultipleObjectsReturned("get() returned more than one %s -- it returned %s! Lookup parameters were %s"
            % (self.model._meta.object_name, num, kwargs))
patch(QuerySet, 'get', queryset_get_with_exception_detail)

from django.test.client import RequestFactory, MULTIPART_CONTENT, urlparse, \
    FakePayload
def post_with_string_data_support(original_function, self, path, data={},
    content_type=MULTIPART_CONTENT, **extra):
    """If the data doesn't have an items() method, then it's probably already
    been converted to a string (encoded), and if we try again we'll call
    the nonexistent items() method and fail, so just don't encode it at
    all."""
    if content_type == MULTIPART_CONTENT and getattr(data, 'items', None) is None:
        parsed = urlparse(path)
        r = {
            'CONTENT_LENGTH': len(data),
            'CONTENT_TYPE':   content_type,
            'PATH_INFO':      self._get_path(parsed),
            'QUERY_STRING':   parsed[4],
            'REQUEST_METHOD': 'POST',
            'wsgi.input':     FakePayload(data),
        }
        r.update(extra)
        return self.request(**r)
    else:
        return original_function(self, path, data, content_type, **extra)
patch(RequestFactory, 'post', post_with_string_data_support)

from django.forms.models import BaseModelForm, InlineForeignKeyField, \
    construct_instance, NON_FIELD_ERRORS
    
from django.core.exceptions import ValidationError

def post_clean_with_simpler_validation(original_function, self):
    """
    Until https://code.djangoproject.com/ticket/16423#comment:3 is implemented,
    patch it in ourselves: do the same validation on objects when called
    from the form, as the object would do on itself.
    """
    
    opts = self._meta
    # Update the model instance with self.cleaned_data.
    # print "construct_instance with password = %s" % self.cleaned_data.get('password')
    self.instance = construct_instance(self, self.instance, opts.fields, opts.exclude)
    # print "constructed instance with password = %s" % self.instance.password

    exclude = self._get_validation_exclusions()

    # Foreign Keys being used to represent inline relationships
    # are excluded from basic field value validation. This is for two
    # reasons: firstly, the value may not be supplied (#12507; the
    # case of providing new values to the admin); secondly the
    # object being referred to may not yet fully exist (#12749).
    # However, these fields *must* be included in uniqueness checks,
    # so this can't be part of _get_validation_exclusions().
    for f_name, field in self.fields.items():
        if isinstance(field, InlineForeignKeyField):
            exclude.append(f_name)

    # Clean the model instance's fields.
    try:
        self.instance.full_clean(exclude)
    except ValidationError, e:
        self._update_errors(e.update_error_dict(None))
patch(BaseModelForm, '_post_clean', post_clean_with_simpler_validation)

from django.forms import BaseForm
def clean_form_with_field_errors(original_function, self):
    """
    Allow BaseForm._clean_form to report errors on individual fields
    as well as the whole form. The standard version only works on the
    whole form.
    """
    
    try:
        self.cleaned_data = self.clean()
    except ValidationError, e:
        if hasattr(e, 'message_dict'):
            for field, error_strings in e.message_dict.items():
                self._errors[field] = self.error_class(error_strings)
        else:
            self._errors[NON_FIELD_ERRORS] = self.error_class(e.messages)
patch(BaseForm, '_clean_form', clean_form_with_field_errors)

from django.core.urlresolvers import RegexURLResolver, NoReverseMatch
from pprint import PrettyPrinter
pp = PrettyPrinter()
def reverse_with_debugging(original_function, self, lookup_view, *args, **kwargs):
    """
    Show all the patterns in the reverse_dict if a reverse lookup fails,
    to help figure out why.
    """
    
    try:
        return original_function(self, lookup_view, *args, **kwargs)
    except NoReverseMatch as e:
        if lookup_view in self.reverse_dict:
            raise NoReverseMatch(str(e) + (" Possible match: %s" %
                (self.reverse_dict[lookup_view],)))
        else:
            raise NoReverseMatch("%s (%s)" % (str(e),
                pp.pformat(self.reverse_dict)))
patch(RegexURLResolver, 'reverse', reverse_with_debugging)

from django.contrib.admin.helpers import Fieldline, AdminField, mark_safe
from admin import CustomAdminReadOnlyField
class FieldlineWithCustomReadOnlyField(object):
    """
    Custom replacement for Fieldline that allows fields in the Admin
    interface to render their own read-only view if they like.
    """
    
    def __init__(self, form, field, readonly_fields=None, model_admin=None):
        self.form = form # A django.forms.Form instance
        if not hasattr(field, "__iter__"):
            self.fields = [field]
        else:
            self.fields = field
        self.model_admin = model_admin
        if readonly_fields is None:
            readonly_fields = ()
        self.readonly_fields = readonly_fields

    def __iter__(self):
        for i, field in enumerate(self.fields):
            if field in self.readonly_fields:
                yield CustomAdminReadOnlyField(self.form, field, is_first=(i == 0),
                    model_admin=self.model_admin)
            else:
                yield AdminField(self.form, field, is_first=(i == 0))

    def errors(self):
        return mark_safe(u'\n'.join([self.form[f].errors.as_ul() for f in self.fields if f not in self.readonly_fields]).strip('\n'))
import django.contrib.admin.helpers
django.contrib.admin.helpers.Fieldline = FieldlineWithCustomReadOnlyField

from django.db.backends.creation import BaseDatabaseCreation
def destroy_test_db_disabled(original_function, self, test_database_name,
    verbosity):
    pass
# patch(BaseDatabaseCreation, 'destroy_test_db', destroy_test_db_disabled)

from django.contrib.auth import models as auth_models
if not hasattr(auth_models.Group, 'natural_key'):
    """
    Allow group lookups by name in fixtures, until
    https://code.djangoproject.com/ticket/13914 lands.
    """
    
    from django.db import models as db_models
    class GroupManagerWithNaturalKey(db_models.Manager):
        def get_by_natural_key(self, name):
            return self.get(name=name)
    # print "auth_models.Group.objects = %s" % auth_models.Group.objects
    del auth_models.Group._default_manager
    GroupManagerWithNaturalKey().contribute_to_class(auth_models.Group, 'objects')
    def group_natural_key(self):
        return (self.name,)
    auth_models.Group.natural_key = group_natural_key

import django.core.serializers.python
def Deserializer_with_debugging(original_function, object_list, **options):
    from django.core.serializers.python import _get_model
    from django.db import DEFAULT_DB_ALIAS
    from django.utils.encoding import smart_unicode
    from django.conf import settings

    print "loading all: %s" % object_list

    db = options.pop('using', DEFAULT_DB_ALIAS)
    db_models.get_apps()
    for d in object_list:
        print "loading %s" % d
        
        # Look up the model and starting build a dict of data for it.
        Model = _get_model(d["model"])
        data = {Model._meta.pk.attname : Model._meta.pk.to_python(d["pk"])}
        m2m_data = {}

        # Handle each field
        for (field_name, field_value) in d["fields"].iteritems():
            if isinstance(field_value, str):
                field_value = smart_unicode(field_value, options.get("encoding", settings.DEFAULT_CHARSET), strings_only=True)

            field = Model._meta.get_field(field_name)

            # Handle M2M relations
            if field.rel and isinstance(field.rel, db_models.ManyToManyRel):
                print "  field = %s" % field
                print "  field.rel = %s" % field.rel
                print "  field.rel.to = %s" % field.rel.to
                print "  field.rel.to._default_manager = %s" % (
                    field.rel.to._default_manager)
                print "  field.rel.to.objects = %s" % (
                    field.rel.to.objects)

                if hasattr(field.rel.to._default_manager, 'get_by_natural_key'):
                    def m2m_convert(value):
                        if hasattr(value, '__iter__'):
                            return field.rel.to._default_manager.db_manager(db).get_by_natural_key(*value).pk
                        else:
                            return smart_unicode(field.rel.to._meta.pk.to_python(value))
                else:
                    m2m_convert = lambda v: smart_unicode(field.rel.to._meta.pk.to_python(v))
                m2m_data[field.name] = [m2m_convert(pk) for pk in field_value]
                for i, pk in enumerate(field_value):
                    print "  %s: converted %s to %s" % (field.name,
                        pk, m2m_data[field.name][i])
    
    result = original_function(object_list, **options)
    print "  result = %s" % result
    import traceback
    traceback.print_stack()
    return result
# patch(django.core.serializers.python, 'Deserializer',
#     Deserializer_with_debugging)

import django.core.serializers.base
def save_with_debugging(original_function, self, save_m2m=True, using=None):
    print "%s.save(save_m2m=%s, using=%s)" % (self, save_m2m, using)
    original_function(self, save_m2m, using)
# patch(django.core.serializers.base.DeserializedObject, 'save',
#     save_with_debugging)

from django.test.utils import ContextList
def ContextList_keys(self):
    keys = set()
    for subcontext in self:
        for dict in subcontext:
            keys |= set(dict.keys())
    return keys
ContextList.keys = ContextList_keys

from django.conf import LazySettings
from django.conf import global_settings
def configure_with_debugging(original_function, self,
    default_settings=global_settings, **options):
    print "LazySettings configured: %s, %s" % (default_settings, options)
    import traceback
    traceback.print_stack()
    return original_function(self, default_settings, **options)
# patch(LazySettings, 'configure', configure_with_debugging)

def setup_with_debugging(original_function, self):
    print "LazySettings setup:"
    import traceback
    traceback.print_stack()
    return original_function(self)
# patch(LazySettings, '_setup', setup_with_debugging)

from django.contrib.admin.views.main import ChangeList
# before(ChangeList, 'get_results')(breakpoint)
# @before(ChangeList, 'get_results')
"""
def get_results_with_debugging(self, request):
    print "get_results query = %s" % object.__str__(self.query_set.query)
"""

# from django.forms.forms import BoundField
# before(BoundField, 'value')(breakpoint)

# Until a patch for 6707 lands: https://code.djangoproject.com/ticket/6707
"""
from django.db.models.fields.related import ReverseManyRelatedObjectsDescriptor
def related_objects_set_without_clear(original_function, self, instance,
    new_values):
    
    if instance is None:
        raise AttributeError("Manager must be accessed via instance")

    if not self.field.rel.through._meta.auto_created:
        opts = self.field.rel.through._meta
        raise AttributeError("Cannot set values on a ManyToManyField which specifies an intermediary model.  Use %s.%s's Manager instead." % (opts.app_label, opts.object_name))

    manager = self.__get__(instance)
    old_values = manager.all()
    values_to_remove = [v for v in old_values 
        if v not in new_values]
    manager.remove(*values_to_remove)
patch(ReverseManyRelatedObjectsDescriptor, '__set__',
    related_objects_set_without_clear)
"""

from django.db.models.fields import AutoField
def AutoField_to_python_with_improved_debugging(original_function, self, value):
    try:
        return original_function(self, value)
    except (TypeError, ValueError):
        raise exceptions.ValidationError(self.error_messages['invalid'] +
            ": %s.%s is not allowed to have value '%s'" % 
            (self.model, self.name, value))
# print "before patch: IntranetUser.id.to_python = %s" % IntranetUser.id.to_python
patch(AutoField, 'to_python', AutoField_to_python_with_improved_debugging)
# print "after patch: IntranetUser.id.to_python = %s" % IntranetUser.id.to_python
