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

from password import PasswordChangeMixin

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

from django.contrib.admin import ModelAdmin
import widgets
class AdminWithReadOnly(ModelAdmin):
    # customise the default display of some form fields:
    formfield_overrides = {
        db_fields.URLField: {'widget': widgets.URLFieldWidgetWithLink},
        db_fields.FileField: {'widget': widgets.AdminFileWidgetWithSize},
        db_fields.ImageField: {'widget': widgets.AdminImageWidgetWithThumbnail},
    }
    
    def formfield_for_dbfield(self, db_field, **kwargs):
        """
        Disable the "add related" option on ForeignKey fields, as
        it will cause difficulties for users if they start adding Programs
        and DocumentTypes!
        
        Allow overriding form field settings by field name as well as
        by class.
        """

        if db_field.name in self.formfield_overrides:
            kwargs = dict(self.formfield_overrides[db_field.name], **kwargs)

        old_formfield = super(AdminWithReadOnly, self).formfield_for_dbfield(
            db_field, **kwargs)
        
        if (hasattr(old_formfield, 'widget') and
            isinstance(old_formfield.widget, widgets.RelatedFieldWidgetWrapper)):

            related_widget = old_formfield.widget
            wrapped_widget = old_formfield.widget.widget
            
            related_widget.can_add_related = False
            
            if hasattr(wrapped_widget, 'has_readonly_view'):
                related_widget.has_readonly_view = wrapped_widget.has_readonly_view
        
        return old_formfield
    
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
            'has_file_field': True, # FIXME - this should check if form or formsets have a FileField,
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
    
        if request.POST: # The user has already confirmed the deletion.
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

class IntranetUserAdminForm(PasswordChangeMixin, ModelForm):
    class Meta:
        model = models.IntranetUser

    password1 = forms.CharField(required=False, label="New password")
    password2 = forms.CharField(required=False, label="Confirm new password")
    
    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, 
        initial=None, error_class=ErrorList, label_suffix=':', 
        empty_permitted=False, instance=None):
        
        # print "IntranetUserForm.__init__: data = %s, initial = %s" % (data, initial)
        super(IntranetUserAdminForm, self).__init__(data=data, files=files,
            auto_id=auto_id, prefix=prefix, initial=initial,
            error_class=error_class, label_suffix=label_suffix, 
            empty_permitted=empty_permitted, instance=instance)

    def clean_groups(self):
        """
        Stop the user from removing themselves from the admins group.
        """
        
        new_groups = self.cleaned_data['groups']
        new_group_ids = [g.id for g in new_groups]
        user_being_updated = self.object_being_updated
        
        # import pdb; pdb.set_trace()
        
        if user_being_updated and user_being_updated.id == self.request.user.pk:
            from models import IntranetGroup
            old_admin_groups = IntranetGroup.objects.filter(administrators=True,
                user__pk=user_being_updated.id)
            
            for group in old_admin_groups:
                if group.id not in new_group_ids:
                    from django.forms import ValidationError
                    raise ValidationError('You cannot demote yourself ' +
                        'from the %s group' % group.name)

            # are any of the new groups administrators groups?            
            will_be_admin = \
                IntranetGroup.objects.filter(administrators=True).in_bulk(new_group_ids)
            # treat a dict as a boolean: empty dict is False, non-empty is True  
            if user_being_updated.is_superuser and not will_be_admin:
                from django.forms import ValidationError
                raise ValidationError('You cannot demote yourself from ' +
                    'being a superuser. You must put yourself in one of ' +
                    'the Administrators groups: %s' % 
                    IntranetGroup.objects.filter(administrators=True))
                
            will_be_inactive = IntranetGroup.objects.filter(inactive=True,
                id__in=new_group_ids)
            if will_be_inactive:
                from django.forms import ValidationError
                raise ValidationError('You cannot place yourself ' +
                    'in the %s group' % will_be_inactive[0].name)
                        
        return new_groups

from django_tables2 import tables

class DocumentsAuthoredTable(tables.Table):
    """
    Basically the same as search.search.SearchTable, but copied here
    in order to avoid introducing a dependency.
    """
    
    title = tables.Column(verbose_name="Title")
    authors = tables.Column(verbose_name="Authors")
    created = tables.Column(verbose_name="Date Added")
    programs = tables.Column(verbose_name="Programs")
    document_type = tables.Column(verbose_name="Document Type")
    
    def render_title(self, value, record):
        # print "record = %s (%s)" % (record, dir(record))
        return mark_safe("<a href='%s'>%s</a>" % (record.get_absolute_url(),
            value))

    def render_authors(self, value):
        users = value.all()
        return ', '.join([user.full_name for user in users])
    
    def render_programs(self, value):
        programs = value.all()
        return ', '.join([program.name for program in programs])
    
    def render_document_type(self, value):
        return value.name
    
    class Meta:
        attrs = {'class': 'paleblue'}
        sortable = False # doesn't make sense on a form, would lose changes

from django.forms.widgets import Widget
class DocumentsAuthoredWidget(Widget):
    """
    A widget that displays documents authored by the user being viewed.
    Actually the data is initialised by
    IntranetUserReadOnlyForm.get_documents_authored(), and just rendered
    into a table here. 
    """

    has_readonly_view = True
    def render(self, name, value, attrs=None):
        # print "DocumentsAuthoredWidget.render(%s, %s)" % (name, value)
        # raise Exception("Where did this value come from?")
        table = DocumentsAuthoredTable(value)
        
        if 'return_table' in attrs:
            return table
        else:
            return table.as_html()
        
class DocumentsAuthoredField(forms.Field):
    """
    A field that displays documents authored by the user being viewed.
    Actually the data is initialised by
    IntranetUserReadOnlyForm.get_documents_authored(), and just rendered here. 
    """
    widget = DocumentsAuthoredWidget

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

class IntranetUserReadOnlyForm(ModelFormWithReadOnly):
    """
    Some ugly stuff to add fields to an admin form:
    http://groups.google.com/group/django-developers/browse_thread/thread/2bfa60a122016d6d
    """

    documents_authored = DocumentsAuthoredField()
    
    class Meta:
        model = models.IntranetUser

    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, 
        initial=None, error_class=ErrorList, label_suffix=':', 
        empty_permitted=False, instance=None):
        
        """
        Add a "method" to the initial data which is used to lookup the
        value of documents_authored by BoundField.
        """
        
        if initial is None:
            initial = {}
        initial['documents_authored'] = lambda: instance.documents_authored.all()
        initial['is_logged_in'] = lambda: instance.is_logged_in()
        
        # print "IntranetUserReadOnlyForm.__init__: data = %s, initial = %s" % (data, initial)
        super(IntranetUserReadOnlyForm, self).__init__(data, files,
            auto_id, prefix, initial, error_class, label_suffix,
            empty_permitted, instance)
        
        self["photo"].field.widget.readonly_template = u'%(thumbnail)s'

class IntranetUserAdmin(AdminWithReadOnly):
    """
    Some ugly stuff to add fields to an admin form:
    http://groups.google.com/group/django-developers/browse_thread/thread/2bfa60a122016d6d
    """
    
    # inlines = [AdminDocumentsInline]
     
    def __init__(self, model, admin_site):
        super(IntranetUserAdmin, self).__init__(model, admin_site)
        
    list_display = ('username', 'full_name', 'job_title', 'program',
        models.IntranetUser.get_userlevel)

    exclude = ['password', 'first_name', 'last_name', 'user_permissions',
        'is_active', 'is_staff', 'is_superuser', 'date_joined']

    def get_form_class(self, request, obj=None, **kwargs):
        if 'form' not in kwargs:
            if request.is_read_only:
                form = IntranetUserReadOnlyForm
            else:
                form = IntranetUserAdminForm
            kwargs['form'] = form
                
        result = super(IntranetUserAdmin, self).get_form_class(request, obj=obj,
            **kwargs)
        # print 'get_form => %s' % dir(result)
        # print 'declared_fields => %s' % result.declared_fields
        # print 'base_fields => %s' % result.base_fields
        result.base_fields['is_logged_in'] = forms.BooleanField(required=False)
        # the request will also be poked into the form by our caller,
        # get_form.
        
        return result

    def render_change_form(self, request, context, add=False, change=False,
        form_url='', obj=None):
        """
        This is called right at the end of change_view. It seems like the
        best place to set fields to read-only.  
        """
        
        adminForm = context['adminform']
        adminForm.readonly_fields = ('is_logged_in',)

        return super(IntranetUserAdmin, self).render_change_form(request,
            context, add=add, change=change, form_url=form_url, obj=obj)
       
    documents_authored = None
     
    """
    def documents_authored(self):
        return "bar"
    """

class ProgramAdmin(admin.ModelAdmin):
    list_display = ('name', 'program_type')
    ordering = ('name',)

from django.contrib.auth.admin import GroupAdmin
class IntranetGroupAdmin(GroupAdmin):
    pass

admin.site.register(models.IntranetUser, IntranetUserAdmin)
admin.site.register(models.IntranetGroup, GroupAdmin)
admin.site.register(models.ProgramType, admin.ModelAdmin)
admin.site.register(models.Program, ProgramAdmin)

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
