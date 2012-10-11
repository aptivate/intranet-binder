from django.contrib.admin.widgets import AdminFileWidget
class AdminFileWidgetWithSize(AdminFileWidget):
    template_with_initial = u'%(initial_text)s: %(link_to_file)s (%(size)s) %(clear_template)s<br />%(input_text)s: %(input)s'
    readonly_template = u'%(link_to_file)s (%(size)s)'
    
    from django.contrib.admin.views.main import EMPTY_CHANGELIST_VALUE
    readonly_unset_template = EMPTY_CHANGELIST_VALUE
    
    has_readonly_view = True

    def extra_context(self, name, value, attrs):
        return {}

    def render(self, name, value, attrs=None):
        from django.forms.widgets import ClearableFileInput
        substitutions = {
            'initial_text': self.initial_text,
            'input_text': self.input_text,
            'clear_template': '',
            'clear_checkbox_label': self.clear_checkbox_label,
        }
        template = u'%(input)s'
        substitutions['input'] = super(ClearableFileInput,
            self).render(name, value, attrs)

        if value and hasattr(value, "url"):
            template = self.template_with_initial
            
            try:
                from django.template.defaultfilters import filesizeformat
                substitutions['size'] = filesizeformat(value.size)
            except OSError as e:
                substitutions['size'] = "Unknown"
            
            from django.utils.encoding import force_unicode
            from django.utils.html import escape, conditional_escape
            substitutions['link_to_file'] = (u'<a href="%s">%s</a>'
                                        % (escape(value.url),
                                           escape(force_unicode(value))))
            
            if not self.is_required:
                checkbox_name = self.clear_checkbox_name(name)
                checkbox_id = self.clear_checkbox_id(checkbox_name)
                substitutions['clear_checkbox_name'] = conditional_escape(checkbox_name)
                substitutions['clear_checkbox_id'] = conditional_escape(checkbox_id)
                
                from django.forms.widgets import CheckboxInput
                substitutions['clear'] = CheckboxInput().render(checkbox_name,
                    False, attrs={'id': checkbox_id})
                substitutions['clear_template'] = self.template_with_clear % substitutions
        
        if attrs.get('readonly'):
            if value and hasattr(value, "url"):
                template = self.readonly_template
            else:
                template = self.readonly_unset_template
        
        substitutions.update(self.extra_context(name, value, attrs))
        
        from django.utils.safestring import mark_safe
        return mark_safe(template % substitutions)

class AdminImageWidgetWithThumbnail(AdminFileWidgetWithSize):
    template_with_initial = u'%(thumbnail)s %(initial_text)s: %(link_to_file)s (%(size)s) %(clear_template)s<br />%(input_text)s: %(input)s'
    readonly_template = u'%(thumbnail)s %(link_to_file)s (%(size)s)'
    thumbnail_template = u'<img class="thumbnail" src="%s" /><br />'
    thumbnail_options = {
        'size': (200, 200),
        'crop': True,
        'bw': False
    }

    def __init__(self, read_write_template=None, read_only_template=None,
        attrs=None):
        super(AdminFileWidgetWithSize, self).__init__(attrs)
        
        if read_write_template is not None:
            self.template_with_initial = read_write_template
            
        if read_only_template is not None:
            self.readonly_template = read_only_template

    def extra_context(self, name, value, attrs):
        context = {}
        if value:
            from django.conf import settings
            thumbnail_url = "%s%s" % (settings.MEDIA_URL,
                self.square_thumbnail(value))
            thumbnail = self.thumbnail_template % thumbnail_url
        else:
            thumbnail = ""
        context['thumbnail'] = thumbnail
        return context
    
    def square_thumbnail(self, source):
        from django.db.models.fields.files import FieldFile
        from easy_thumbnails.files import get_thumbnailer
        
        if isinstance(source, FieldFile):
            nailer = get_thumbnailer(source) # caches the thumbnail
        else:
            # should be a File-like object at least. No caching.
            nailer = get_thumbnailer(source, relative_name=source.name)
            
        return nailer.get_thumbnail(self.thumbnail_options)

from django.contrib.admin.widgets import AdminURLFieldWidget
class URLFieldWidgetWithLink(AdminURLFieldWidget):
    def render(self, name, value, attrs=None):
        html = super(URLFieldWidgetWithLink, self).render(name, value,
            attrs=attrs)

        if value is not None:
            final_attrs = dict(href=value, target='_blank')
            from django.forms.util import flatatt as attributes_to_str
            html += " <a %s>(open)</a>" % attributes_to_str(final_attrs)
        
        from django.utils.safestring import mark_safe
        return mark_safe(html)

from django.contrib.admin.widgets import RelatedFieldWidgetWrapper
class RelatedFieldWithoutAddLink(RelatedFieldWidgetWrapper):
    def __init__(self, widget, rel, admin_site, can_add_related=None):
        RelatedFieldWidgetWrapper.__init__(self, widget, rel, admin_site,
            can_add_related=False)

from django.forms.widgets import CheckboxInput
class AdminYesNoWidget(CheckboxInput):
    has_readonly_view = True

    def render(self, name, value, attrs=None):
        if attrs is not None and attrs.get('readonly'):
            if value:
                return "Yes"
            else:
                return "No"
        else:
            return super(AdminYesNoWidget, self).render(name, value, attrs)

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
        from django.utils.safestring import mark_safe
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
        table = DocumentsAuthoredTable(value)
        
        if 'return_table' in attrs:
            return table
        else:
            return table.as_html()

from django import forms        
class DocumentsAuthoredField(forms.Field):
    """
    A field that displays documents authored by the user being viewed.
    Actually the data is initialised by
    IntranetUserReadOnlyForm.get_documents_authored(), and just rendered here. 
    """
    widget = DocumentsAuthoredWidget

class ProgramWithProgramTypeWidget(Widget):
    """
    A widget that displays the user's program and their program type.
    """

    has_readonly_view = True
    def render(self, name, value, attrs=None):
        table = DocumentsAuthoredTable(value)
        
        if 'return_table' in attrs:
            return table
        else:
            return table.as_html()
