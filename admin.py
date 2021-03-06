# https://code.djangoproject.com/ticket/16929

import django.contrib.admin
import models

from django import forms, template
from django.contrib import admin
from django.contrib.admin.options import csrf_protect_m
from django.contrib.admin.util import unquote
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db import models as db_fields
from django.db import transaction, router
from django.forms import ModelForm
from django.forms import fields as form_fields
from django.forms.util import ErrorList
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.utils.encoding import force_unicode
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _

# from django.utils.decorators import method_decorator
# from django.views.decorators.csrf import csrf_protect

# csrf_protect_m = method_decorator(csrf_protect)
# from django.db import transaction
# from models import IntranetUser

from django.contrib.admin.views.main import ChangeList
class ChangeListWithLinksToReadOnlyView(ChangeList):
    def url_for_result(self, result):
        opts = self.model._meta
        info = opts.app_label, opts.module_name
        return reverse('admin:%s_%s_readonly' % info,
            args=[getattr(result, self.pk_attname)])

class TemplateChoiceMixin(object):
    """
    Mixin for ModelChoiceField to allow changing the format of the field's
    rendered text without creating a custom subclass, by passing a
    "template" parameter.
    """

    template = u'{{ obj }}'
    context = {}

    def __init__(self, template=None, context=None, *args, **kwargs):
        from django.template import Template
        self.template = Template(template if template else self.template)
        self.context = context if context else self.context
        super(TemplateChoiceMixin, self).__init__(*args, **kwargs)

    def label_from_instance(self, obj):
        """
        This method is used to convert objects into strings; it's used to
        generate the labels for the choices presented by this object.

        TemplatedModelChoiceField renders the template provided in the
        "template" kwarg to the constructor, passing "obj" (the current list item)
        and "context" (self.context) as the dictionary to interpolate with,
        so you can use "{{ obj.blah }} and {{ context.whee }}" as the template.
        """
        from django.template import Context
        return self.template.render(Context({
            'obj': obj, 'field': self, 'context': self.context
            }))

from django.forms.models import ModelChoiceField, ModelMultipleChoiceField
class TemplatedModelChoiceField(TemplateChoiceMixin, ModelChoiceField):
    pass
class TemplatedModelMultipleChoiceField(TemplateChoiceMixin,
    ModelMultipleChoiceField):
    pass

def defer_save_signal(original_function):
    from django.db.models import signals

    def wrapper(*args, **kwargs):
        old_receivers = signals.post_save.receivers
        signals.post_save.receivers = []

        captured = []
        def capture_args_receiver(signal, sender, **named):
            captured.append({
                'sender': sender,
                'kwargs': named
                })
        signals.post_save.connect(capture_args_receiver, sender=None)

        try:
            return original_function(*args, **kwargs)
        finally:
            signals.post_save.receivers = old_receivers
            for capture in captured:
                signals.post_save.send(sender=capture['sender'],
                    **capture['kwargs'])

    return wrapper

class AllowOverrideAdminFormFieldByNameMixin(object):
    """
    Allows overriding form field settings by field name instead of
    by class. For example:

    class MyModelAdmin(ModelAdmin):
        formfield_overrides = {
            'photo': {'widget': widgets.AdminImageWidgetWithThumbnail}
            db_fields.URLField: {'widget': widgets.URLFieldWidgetWithLink},
        }
    """

    def formfield_for_dbfield(self, db_field, **kwargs):
        if db_field.name in self.formfield_overrides:
            kwargs = dict(self.formfield_overrides[db_field.name], **kwargs)

        return super(AllowOverrideAdminFormFieldByNameMixin,
            self).formfield_for_dbfield(db_field, **kwargs)

class DisableAddRelatedMixin(object):
    """
    Mix this class into your ModelAdmin, BEFORE the ModelAdmin
    base class, to disable the "add related" option on ForeignKey
    fields. There appears to be no other way to disable it.
    """

    def formfield_for_dbfield(self, db_field, **kwargs):
        old_formfield = super(DisableAddRelatedMixin,
            self).formfield_for_dbfield(db_field, **kwargs)

        if (hasattr(old_formfield, 'widget') and
            isinstance(old_formfield.widget, widgets.RelatedFieldWidgetWrapper)):

            related_widget = old_formfield.widget
            wrapped_widget = old_formfield.widget.widget

            related_widget.can_add_related = False

            if hasattr(wrapped_widget, 'has_readonly_view'):
                related_widget.has_readonly_view = wrapped_widget.has_readonly_view

        return old_formfield

from django.contrib.admin import ModelAdmin
import widgets
class AdminWithReadOnly(AllowOverrideAdminFormFieldByNameMixin,
    DisableAddRelatedMixin, ModelAdmin):

    # customise the default display of some form fields:
    formfield_overrides = {
        db_fields.URLField: {'widget': widgets.URLFieldWidgetWithLink},
        db_fields.FileField: {'widget': widgets.AdminFileWidgetWithSize},
        db_fields.ImageField: {'widget': widgets.AdminImageWidgetWithThumbnail},
    }

    def __init__(self, model, admin_site):
        """
        Every model that uses an AdminWithReadOnly needs a view_ permission
        as well. Rather than forcing users to hard-code this, I hope we
        can create it here. As the Admin class is instantiated when it's
        registered, and that usually happens when the file that registers
        it is read, this should be early enough that we can create fixtures
        for group permissions, trusting that the permission records already
        exist by that point.
        """

        # Copied from django/contrib/management/__init__.py, which
        # is unfortunately not reusable.

        # This will hold the permissions we're looking for as
        # (content_type, (codename, name))

        # The codenames and ctypes that should exist.
        from django.contrib.contenttypes.models import ContentType
        ctype = ContentType.objects.get_for_model(model)
        ctypes = set((ctype,))

        from django.contrib.auth.management import _get_permission_codename
        view_perm = (_get_permission_codename('view', model._meta),
            u'Can %s %s' % ('view', model._meta.verbose_name_raw))
        expected_perms = ((ctype, view_perm),)

        # Find all the Permissions that have a context_type for a model we're
        # looking for.  We don't need to check for codenames since we already have
        # a list of the ones we're going to create.
        from django.contrib.auth import models as auth_app
        found_perms = set(auth_app.Permission.objects.filter(
            content_type__in=ctypes,
        ).values_list(
            "content_type", "codename"
        ))

        objs = [
            auth_app.Permission(codename=codename, name=name, content_type=ctype)
            for ctype, (codename, name) in expected_perms
            if (ctype.pk, codename) not in found_perms
        ]

        for ctype, (codename, name) in expected_perms:
            # If the permissions exists, move on.
            if (ctype.pk, codename) in found_perms:
                continue
            p = auth_app.Permission.objects.create(
                codename=codename,
                name=name,
                content_type=ctype
            )

        super(AdminWithReadOnly, self).__init__(model, admin_site)

    def get_urls(self):
        """
        Add a URL pattern for a read-only view to the default admin views.
        Place key called "read_only" with value True in the context which
        ends up being passed to render_change_form().
        """
        from django.utils.functional import update_wrapper

        def wrap(view):
            def wrapper(*args, **kwargs):
                return self.admin_site.admin_view(view)(*args, **kwargs)
            return update_wrapper(wrapper, view)

        try:
            from django.conf.urls import url
        except ImportError:
            from django.conf.urls.defaults import url
        from django.utils.encoding import force_unicode

        opts = self.model._meta
        info = opts.app_label, opts.module_name
        extra_context = {
            'read_only': True,
            'title': 'View %s' % force_unicode(opts.verbose_name),
            'change_view': 'admin:%s_%s_change' % info,
        }

        urlpatterns = [url(r'^$',
                wrap(self.changelist_view),
                name='%s_%s_changelist' % info),
            url(r'^add/$',
                wrap(self.add_view),
                name='%s_%s_add' % info),
            url(r'^(.+)/history/$',
                wrap(self.history_view),
                name='%s_%s_history' % info),
            url(r'^(.+)/delete/$',
                wrap(self.delete_view),
                name='%s_%s_delete' % info),
            url(r'^(.+)/$',
                wrap(self.change_view),
                name='%s_%s_change' % info),
            url(r'^(.+)/readonly$',
                wrap(self.change_view),
                {'extra_context': extra_context},
                name='%s_%s_readonly' % info)]

        return urlpatterns

    def get_view_permission(self):
        return 'view_%s' % self.opts.object_name.lower()

    def has_view_permission(self, request, obj=None):
        """
        Returns True if the given request has permission to view an object.
        Can be overriden by the user in subclasses.
        """
        opts = self.opts
        return request.user.has_perm(opts.app_label + '.' + self.get_view_permission())

    def has_change_permission(self, request, obj=None):
        """
        Returns True if the given request has permission to change the given
        Django model instance. Overridden to allow us to reuse change_view
        as a read-only view, by pretending to have "change" permissions when
        the access is read-only.
        """

        if (request.user.is_authenticated() and
            getattr(request, 'is_read_only', False) and
            request.method == 'GET' and
            self.has_view_permission(request, obj)):

            return True

        return super(AdminWithReadOnly, self).has_change_permission(request,
            obj)

    def changelist_view(self, request, extra_context=None):
        request.is_read_only = True
        return super(AdminWithReadOnly, self).changelist_view(request, extra_context)

    @defer_save_signal
    def add_view(self, request, form_url='', extra_context=None):
        """
        In order for get_form() to know whether this is a read-only form,
        not having access to the extra_context, we have to poke something
        into the request to help it.
        """
        request.is_read_only = (extra_context is not None and
            'read_only' in extra_context)
        return super(AdminWithReadOnly, self).add_view(request, form_url,
            extra_context)

    @defer_save_signal
    def change_view(self, request, object_id, extra_context=None):
        """
        In order for get_form() to know whether this is a read-only form,
        not having access to the extra_context, we have to poke something
        into the request to help it.
        """
        request.is_read_only = (extra_context is not None and
            'read_only' in extra_context)
        return super(AdminWithReadOnly, self).change_view(request, object_id,
            extra_context)

    def render_change_form(self, request, context, add=False, change=False,
        form_url='', obj=None):
        """
        This is called right at the end of change_view. It seems like the
        best place to set all fields to read-only if this is a read-only
        view, as the fields have already been calculated and are available
        to us. We shouldn't really muck about with the internals of the
        AdminForm object, but this seems like the cleanest (least invasive)
        solution to making a completely read-only admin form.
        """

        opts = self.model._meta
        app_label = opts.app_label

        if 'read_only' in context:
            adminForm = context['adminform']
            readonly = []
            for name, options in adminForm.fieldsets:
                readonly.extend(options['fields'])
            adminForm.readonly_fields = readonly
            form_template = [
                "admin/%s/%s/view_form.html" % (app_label, opts.object_name.lower()),
                "admin/%s/view_form.html" % app_label,
                "admin/view_form.html"
            ]
        else:
            form_template = None

        context['referrer'] = request.META.get('HTTP_REFERER')

        is_popup = context['is_popup']

        # We call the superclass' has_change_permission method here,
        # because if we're looking at a read-only view, our own
        # has_change_permission always returns True, even if the user
        # doesn't really have the change permission, and here we want to
        # know if they really do have that permission.
        has_change_permission = (obj is not None and
            super(AdminWithReadOnly, self).has_change_permission(request, obj))
        has_delete_permission = (obj is not None and
            self.has_delete_permission(request, obj))

        context['show_edit_link'] = (not is_popup and has_change_permission)
        context['show_delete_link'] = (not is_popup and has_delete_permission)

        """
        return django.contrib.admin.ModelAdmin.render_change_form(self,
            request, context, add=add, change=change, form_url=form_url,
            obj=obj)
        """

        # What follows was copied from super.render_change_form and
        # adapted to allow passing in a custom template by making
        # form_template an optional method parameter, defaulting to None

        from django.contrib.contenttypes.models import ContentType

        ordered_objects = opts.get_ordered_objects()
        context.update({
            'add': add,
            'change': change,
            'has_add_permission': self.has_add_permission(request),
            'has_change_permission': has_change_permission,
            'has_delete_permission': has_delete_permission,
            'has_file_field': True,  # FIXME - this should check if form or formsets have a FileField,
            'has_absolute_url': hasattr(self.model, 'get_absolute_url'),
            'ordered_objects': ordered_objects,
            'form_url': mark_safe(form_url),
            'opts': opts,
            'content_type_id': ContentType.objects.get_for_model(self.model).id,
            'save_as': self.save_as,
            'save_on_top': self.save_on_top,
            'root_path': self.admin_site.root_path,
        })

        if form_template is None:
            if add and self.add_form_template is not None:
                form_template = self.add_form_template
            else:
                form_template = self.change_form_template

        context_instance = template.RequestContext(request, current_app=self.admin_site.name)
        return render_to_response(form_template or [
            "admin/%s/%s/change_form.html" % (app_label, opts.object_name.lower()),
            "admin/%s/change_form.html" % app_label,
            "admin/change_form.html"
        ], context, context_instance=context_instance)

    def get_changelist(self, request, **kwargs):
        """
        Return a custom ChangeList that links each object to the read-only
        view instead of the editable one.
        """
        return ChangeListWithLinksToReadOnlyView

    # remove when https://code.djangoproject.com/ticket/17962 lands
    @csrf_protect_m
    @transaction.commit_on_success
    def get_deleted_objects(self, objs, opts, request, using):

        return django.contrib.admin.util.get_deleted_objects(objs, opts,
            request.user, self.admin_site, using)

    # remove when https://code.djangoproject.com/ticket/17962 lands
    @csrf_protect_m
    @transaction.commit_on_success
    def delete_view(self, request, object_id, extra_context=None):
        "The 'delete' admin view for this model."
        opts = self.model._meta
        app_label = opts.app_label

        obj = self.get_object(request, unquote(object_id))

        if not self.has_delete_permission(request, obj):
            raise PermissionDenied

        if obj is None:
            raise Http404(_('%(name)s object with primary key %(key)r does not exist.') % {'name': force_unicode(opts.verbose_name), 'key': escape(object_id)})

        using = router.db_for_write(self.model)

        # Populate deleted_objects, a data structure of all related objects that
        # will also be deleted.
        (deleted_objects, perms_needed, protected) = self.get_deleted_objects(
            [obj], opts, request, using)

        if request.POST:  # The user has already confirmed the deletion.
            if perms_needed:
                raise PermissionDenied
            obj_display = force_unicode(obj)
            self.log_deletion(request, obj, obj_display)
            self.delete_model(request, obj)

            self.message_user(request, _('The %(name)s "%(obj)s" was deleted successfully.') % {'name': force_unicode(opts.verbose_name), 'obj': force_unicode(obj_display)})

            if not self.has_change_permission(request, None):
                return HttpResponseRedirect("../../../../")
            return HttpResponseRedirect("../../")

        object_name = force_unicode(opts.verbose_name)

        if perms_needed or protected:
            title = _("Cannot delete %(name)s") % {"name": object_name}
        else:
            title = _("Are you sure?")

        context = {
            "title": title,
            "object_name": object_name,
            "object": obj,
            "deleted_objects": deleted_objects,
            "perms_lacking": perms_needed,
            "protected": protected,
            "opts": opts,
            "root_path": self.admin_site.root_path,
            "app_label": app_label,
        }
        context.update(extra_context or {})
        context_instance = template.RequestContext(request, current_app=self.admin_site.name)
        return render_to_response(self.delete_confirmation_template or [
            "admin/%s/%s/delete_confirmation.html" % (app_label, opts.object_name.lower()),
            "admin/%s/delete_confirmation.html" % app_label,
            "admin/delete_confirmation.html"
        ], context, context_instance=context_instance)

    def get_fieldsets(self, request, obj=None):
        """
        Hook for overriding the fieldsets for the forms generated by
        ModelAdmin's add_view and change_view methods. obj will be None
        if called from add_view, and the object being modified if called
        from change_view.

        Overridden from ModelAdmin because that version tends to
        duplicate fields listed in readonly_fields. Tested by
        DocumentsModuleTest.test_document_admin_form_without_duplicate_fields.
        """

        if self.declared_fieldsets:
            return self.declared_fieldsets
        form = self.get_form(request, obj)

        from ordered_set import OrderedSet
        fields = OrderedSet(form.base_fields.keys()) \
            | OrderedSet(self.get_readonly_fields(request, obj))
        return [(None, {'fields': fields})]

    def get_form_class(self, request, obj=None, **kwargs):
        """
        Hook for changing the form class returned by get_form(), without
        losing the request-poking behaviour.

        The default implementation below calls ModelAdmin's get_form method,
        which overrides ModelForm's automatic fieldsets using
        our Meta class declared_fieldsets and exclude attributes.
        However you can easily override this method to return any form
        class that you'd prefer to use instead. Fields in that form will
        still not be rendered by the AdminForm unless get_fieldsets returns
        them as well.
        """

        return super(AdminWithReadOnly, self).get_form(request, obj,
            **kwargs)

    def get_form(self, request, obj=None, **kwargs):
        """
        Some of our forms needs to know who the current user is, but
        they doesn't normally have access to the request to find out;
        or to the object ID for that matter. So we poke both of these
        into the form instance.

        Unfortunately, this function doesn't return a form object, but a
        form class, so we can't just stuff the request into it. But we can
        return a curried generator function instead, taking advantage of
        duck typing and how Python constructors work, and ModelAdmin will
        construct an instance of our form by calling the generator.

        If you just want to change the class of form returned, you can just
        override get_form_class() instead.
        """

        form_class = self.get_form_class(request, obj, **kwargs)

        def generator(data=None, files=None, auto_id='id_%s', prefix=None,
            initial=None, error_class=ErrorList, label_suffix=':',
            empty_permitted=False, instance=None):

            new_instance = form_class(data, files, auto_id, prefix, initial,
                error_class, label_suffix, empty_permitted, instance)
            new_instance.request = request
            new_instance.object_being_updated = obj
            return new_instance

        # to keep ModelAdmin.get_fieldsets() happy:
        generator.base_fields = form_class.base_fields

        return generator

from django.forms.forms import BoundField
class BoundFieldWithReadOnly(BoundField):
    def readonly(self):
        from django.forms.fields import ChoiceField
        from django.forms.models import ModelChoiceField

        value = self.value()

        if hasattr(self.field.widget, 'has_readonly_view'):
            return self.as_widget(attrs={'readonly': True})
        elif isinstance(self.field, ModelChoiceField):
            if value is None:
                return None
            try:
                return self.field.queryset.get(pk=value)
            except self.field.queryset.model.DoesNotExist as e:
                return "Unknown value %s" % value
        elif isinstance(self.field, ChoiceField):
            try:
                return [choice[1] for choice in self.field.choices
                    if choice[0] == value][0]
            except Exception as e:
                return "Unknown value %s" % value
        else:
            return value
        #
        #    return super(CustomAdminReadOnlyField, self).contents()

class ModelFormWithReadOnly(ModelForm):
    def __getitem__(self, name):
        "Returns a ReadOnlyBoundField with the given name."
        try:
            field = self.fields[name]
        except KeyError:
            raise KeyError('Key %r not found in Form' % name)
        return BoundFieldWithReadOnly(self, field, name)

from django.contrib.admin.helpers import AdminReadonlyField
class CustomAdminReadOnlyField(AdminReadonlyField):
    """
    Allow widgets that support a custom read-only view to declare it,
    by implementing a has_readonly_view attribute, and responding to
    their render() method differently if readonly=True is passed to it.
    """

    def contents(self, **widget_extra_attrs):
        widget_attrs = {'readonly': True}

        if widget_extra_attrs is not None:
            widget_attrs.update(widget_extra_attrs)

        form = self.form
        field = self.field['field']
        # print "CustomAdminReadOnlyField.contents: form = %s, is_bound = %s" % (
        #    form.__class__, form.is_bound)

        if hasattr(form[field].field.widget, 'has_readonly_view'):
            return form[field].as_widget(attrs=widget_attrs)
        else:
            return super(CustomAdminReadOnlyField, self).contents()

    # patch for https://code.djangoproject.com/ticket/16433
    def help_text_for_field(self, name, model):
        from django.db import models
        from django.utils.encoding import smart_unicode

        try:
            help_text = model._meta.get_field_by_name(name)[0].help_text
        except (models.FieldDoesNotExist, AttributeError):
            help_text = ""
        return smart_unicode(help_text)

    # patch __init__ to use the patched help_text_for_field method
    def __init__(self, form, field, is_first, model_admin=None):
        from django.contrib.admin.util import label_for_field
        label = label_for_field(field, form._meta.model, model_admin)

        # Make self.field look a little bit like a field. This means that
        # {{ field.name }} must be a useful class name to identify the field.
        # For convenience, store other field-related data here too.
        if callable(field):
            class_name = field.__name__ != '<lambda>' and field.__name__ or ''
        else:
            class_name = field
        self.field = {
            'name': class_name,
            'label': label,
            'field': field,
            'help_text': self.help_text_for_field(class_name, form._meta.model)
        }
        self.form = form
        self.model_admin = model_admin
        self.is_first = is_first
        self.is_checkbox = False
        self.is_readonly = True
