# https://code.djangoproject.com/ticket/16929

"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from models import UserProfile

# Define an inline admin descriptor for UserProfile model
# which acts a bit like a singleton
import django.contrib.admin.options
class UserProfileInline(django.contrib.admin.options.StackedInline):
    template = 'admin/includes/embedded_fieldset.html'
    model = UserProfile
    fk_name = 'user'
    can_delete = False
    max_num = 1 
    verbose_name_plural = 'profile'

# Define a new User admin
class UserAdminWithProfile(UserAdmin):
    inlines = (UserProfileInline, )

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdminWithProfile)
"""

import django.contrib.admin
from django.contrib import admin
from django.core.urlresolvers import reverse
from django.db import models as db_fields
from django.forms.util import flatatt as attributes_to_str
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
            except OSError:
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
        """
        
        old_formfield = django.contrib.admin.ModelAdmin.formfield_for_dbfield(
            self, db_field, **kwargs)
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
        
