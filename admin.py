# https://code.djangoproject.com/ticket/16929

import django.contrib.admin
import django.db.models
import models

from django import forms
from django.contrib import admin
from django.core.urlresolvers import reverse
from django.db import models as db_fields
from django.forms import ModelForm
from django.forms.util import flatatt as attributes_to_str
from django.forms.util import ErrorList
from django.forms import widgets
from django.template.defaultfilters import filesizeformat
from django.utils.encoding import force_unicode
from django.utils.html import escape, conditional_escape
from django.utils.safestring import mark_safe

# from django.utils.decorators import method_decorator
# from django.views.decorators.csrf import csrf_protect

# csrf_protect_m = method_decorator(csrf_protect)
# from django.db import transaction
# from models import IntranetUser

class AdminFileWidgetWithSize(admin.widgets.AdminFileWidget):
    template_with_initial = u'%(initial_text)s: %(link_to_file)s (%(size)s) %(clear_template)s<br />%(input_text)s: %(input)s'
    readonly_template = u'%(link_to_file)s (%(size)s)'
    
    from django.contrib.admin.views.main import EMPTY_CHANGELIST_VALUE
    readonly_unset_template = EMPTY_CHANGELIST_VALUE
    
    has_readonly_view = True

    def render(self, name, value, attrs=None):
        substitutions = {
            'initial_text': self.initial_text,
            'input_text': self.input_text,
            'clear_template': '',
            'clear_checkbox_label': self.clear_checkbox_label,
        }
        template = u'%(input)s'
        substitutions['input'] = super(widgets.ClearableFileInput,
            self).render(name, value, attrs)

        if value and hasattr(value, "url"):
            template = self.template_with_initial
            try:
                substitutions['size'] = filesizeformat(value.size)
            except OSError as e:
                substitutions['size'] = "Unknown"
            substitutions['link_to_file'] = (u'<a href="%s">%s</a>'
                                        % (escape(value.url),
                                           escape(force_unicode(value))))
            if not self.is_required:
                checkbox_name = self.clear_checkbox_name(name)
                checkbox_id = self.clear_checkbox_id(checkbox_name)
                substitutions['clear_checkbox_name'] = conditional_escape(checkbox_name)
                substitutions['clear_checkbox_id'] = conditional_escape(checkbox_id)
                substitutions['clear'] = widgets.CheckboxInput().render(checkbox_name,
                    False, attrs={'id': checkbox_id})
                substitutions['clear_template'] = self.template_with_clear % substitutions
        
        if attrs.get('readonly'):
            if value and hasattr(value, "url"):
                template = self.readonly_template
            else:
                template = self.readonly_unset_template
        
        return mark_safe(template % substitutions)

class URLFieldWidgetWithLink(admin.widgets.AdminURLFieldWidget):
    def render(self, name, value, attrs=None):
        html = admin.widgets.AdminURLFieldWidget.render(self, name, value,
            attrs=attrs)

        if value is not None:
            final_attrs = dict(href=value, target='_blank')
            html += " <a %s>(open)</a>" % attributes_to_str(final_attrs)
        
        return mark_safe(html)

from django.contrib.admin.widgets import RelatedFieldWidgetWrapper
class RelatedFieldWithoutAddLink(RelatedFieldWidgetWrapper):
    def __init__(self, widget, rel, admin_site, can_add_related=None):
        RelatedFieldWidgetWrapper.__init__(self, widget, rel, admin_site,
            can_add_related=False)

from django.contrib.admin.views.main import ChangeList
class ChangeListWithLinksToReadOnlyView(ChangeList):
    def url_for_result(self, result):
        opts = self.model._meta
        info = opts.app_label, opts.module_name
        return reverse('admin:%s_%s_readonly' % info,
            args=[getattr(result, self.pk_attname)])

from django.contrib.admin import ModelAdmin
class AdminWithReadOnly(ModelAdmin):
    # customise the default display of some form fields:
    formfield_overrides = {
        db_fields.URLField: {'widget': URLFieldWidgetWithLink},
        db_fields.FileField: {'widget': AdminFileWidgetWithSize},
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
            isinstance(old_formfield.widget, RelatedFieldWidgetWrapper)):
            old_formfield.widget.can_add_related = False
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
    
    def has_change_permission(self, request, obj=None):
        """
        Returns True if the given request has permission to change the given
        Django model instance. Overridden to allow us to reuse change_view
        as a read-only view, by pretending to have "change" permissions when
        the access is read-only.
        """
        
        if request.user.is_authenticated() and \
        getattr(request, 'is_read_only', False) and \
        request.method == 'GET':
            return True

        return super(AdminWithReadOnly, self).has_change_permission(request,
            obj)
    
    def changelist_view(self, request, extra_context=None):
        request.is_read_only = True
        return super(AdminWithReadOnly, self).changelist_view(request, extra_context)

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
        
        if 'read_only' in context:
            adminForm = context['adminform']
            readonly = []
            for name, options in adminForm.fieldsets:
                readonly.extend(options['fields'])
            adminForm.readonly_fields = readonly
            form_template = 'admin/view_form.html'
        else:
            form_template = None

        context['referrer'] = request.META.get('HTTP_REFERER')

        is_popup = context['is_popup']
        
        context['show_delete_link'] = (not is_popup and
            self.has_delete_permission(request, obj))
        
        context['show_edit_link'] = (not is_popup and
            super(AdminWithReadOnly, self).has_change_permission(request, obj))
         
        """
        return django.contrib.admin.ModelAdmin.render_change_form(self,
            request, context, add=add, change=change, form_url=form_url,
            obj=obj)
        """
        
        # What follows was copied from super.render_change_form and
        # adapted to allow passing in a custom template by making
        # form_template an optional method parameter, defaulting to None
        
        from django.utils.safestring import mark_safe
        from django.contrib.contenttypes.models import ContentType
        from django import template
        from django.shortcuts import render_to_response

        opts = self.model._meta
        app_label = opts.app_label
        ordered_objects = opts.get_ordered_objects()
        context.update({
            'add': add,
            'change': change,
            'has_add_permission': self.has_add_permission(request),
            'has_change_permission': self.has_change_permission(request, obj),
            'has_delete_permission': self.has_delete_permission(request, obj),
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
    
class IntranetUserForm(ModelForm):
    class Meta:
        model = models.IntranetUser
    
    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, 
        initial=None, error_class=ErrorList, label_suffix=':', 
        empty_permitted=False, instance=None):
        # print "IntranetUserForm.__init__: data = %s, initial = %s" % (data, initial)
        super(IntranetUserForm, self).__init__(data=data, files=files, auto_id=auto_id, prefix=prefix, initial=initial, error_class=error_class, label_suffix=label_suffix, empty_permitted=empty_permitted, instance=instance)
    
    password1 = forms.CharField(required=False, label="New password")
    password2 = forms.CharField(required=False, label="Confirm new password")
    
    COMPLETE_BOTH = 'You must complete both password boxes to set or ' + \
        'change the password'
        
    def clean(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        
        from django.core.exceptions import ValidationError
        
        if password2 and not password1:
            raise ValidationError({'password1': [self.COMPLETE_BOTH]})

        if password1 and not password2:
            raise ValidationError({'password2': [self.COMPLETE_BOTH]})
        
        if password1 and password2:
            if password1 != password2:
                raise ValidationError({'password2': ['Please enter ' +
                    'the same password in both boxes.']})
        
        return ModelForm.clean(self)

    def _post_clean(self):
        ModelForm._post_clean(self)

        # because password is excluded from the form, it's not updated
        # in the model instance, so it's never changed unless we poke it
        # in here.
        
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2:
            if password1 == password2:
                self.instance.set_password(password1)

from django_tables2 import tables
from models import IntranetUser, Program

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

class DocumentsAuthoredWidget(widgets.Widget):
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

class IntranetUserReadOnlyForm(ModelForm):
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
        from django.utils.functional import curry
        initial['documents_authored'] = curry(self.get_documents_authored, instance)
        
        # print "IntranetUserReadOnlyForm.__init__: data = %s, initial = %s" % (data, initial)
        super(IntranetUserReadOnlyForm, self).__init__(data, files,
            auto_id, prefix, initial, error_class, label_suffix,
            empty_permitted, instance)
        
    def get_documents_authored(self, instance):
        # print "get_documents_authored(%s)" % instance
        return instance.document_set.all()

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

    exclude = ['password', 'first_name', 'last_name', 'user_permissions']

    formfield_overrides = {
        django.db.models.URLField: {'widget': URLFieldWidgetWithLink},
        django.db.models.FileField: {'widget': AdminFileWidgetWithSize},
        django.db.models.ImageField: {'widget': AdminFileWidgetWithSize},
    }

    def get_form(self, request, obj=None, **kwargs):
        if 'form' not in kwargs:
            if request.is_read_only:
                form = IntranetUserReadOnlyForm
            else:
                form = IntranetUserForm
            kwargs['form'] = form
                
        result = super(IntranetUserAdmin, self).get_form(request, obj=obj,
            **kwargs)
        # print 'get_form => %s' % dir(result)
        # print 'declared_fields => %s' % result.declared_fields
        # print 'base_fields => %s' % result.base_fields
        result.base_fields['is_logged_in'] = forms.BooleanField(required=False)
        
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

admin.site.register(models.IntranetUser, IntranetUserAdmin)
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
            return AdminReadonlyField.contents(self)
        
