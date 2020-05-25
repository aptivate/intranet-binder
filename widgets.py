from django.contrib.admin.widgets import AdminFileWidget
class AdminFileWidgetWithSize(AdminFileWidget):
    template_with_initial = '%(initial_text)s: %(link_to_file)s (%(size)s) %(clear_template)s<br />%(input_text)s: %(input)s'
    readonly_template = '%(link_to_file)s (%(size)s)'
   
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
        template = '%(input)s'
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
            substitutions['link_to_file'] = ('<a href="%s">%s</a>'
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
                # TODO: Is this correct? What is we don't have a value?
                template = value.model_admin.get_empty_value_display()
        
        substitutions.update(self.extra_context(name, value, attrs))
        
        from django.utils.safestring import mark_safe
        return mark_safe(template % substitutions)

class AdminImageWidgetWithThumbnail(AdminFileWidgetWithSize):
    template_with_initial = '%(thumbnail)s %(initial_text)s: %(link_to_file)s (%(size)s) %(clear_template)s<br />%(input_text)s: %(input)s'
    readonly_template = '%(thumbnail)s %(link_to_file)s (%(size)s)'
    thumbnail_template = '<img class="thumbnail" src="%s" /><br />'
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

class CheckboxInputWithEmptyValueSupport(CheckboxInput):
    """
    Allow writing an empty value attribute, so that our javascript can
    recognise the All Items checkbox by its value.
    """
    
    def render(self, name, value, attrs=None):
        final_attrs = self.build_attrs(attrs, type='checkbox', name=name)
        
        if self.check_test(value):
            final_attrs['checked'] = 'checked'
        
        if not (value is True or value is False or value is None):
            # Only add the 'value' attribute if a value is non-empty.
            from django.utils.encoding import force_text
            final_attrs['value'] = force_text(value)

        from django.utils.html import format_html
        from django.forms.util import flatatt
        return format_html('<input{0} />', flatatt(final_attrs))

from django.forms.widgets import CheckboxSelectMultiple
class ConfigurableCheckboxSelectMultiple(CheckboxSelectMultiple):
    """
    Configurable version of forms.widgets.CheckboxSelectMultiple.
    
    You can add HTML attributes for Javascript hooks, or extra choices
    to the list (that could be used by your Javascript) using the
    widgets override in ModelForm's Meta class, like this:
    
    class OrderForm(forms.ModelForm):
        class Meta:
            widgets = {
                'grades': CheckboxSelectMultipleWithOptions({
                    'checkbox_attrs': {
                        'onchange': 'return checkboxes_changed();',
                    },
                    'extra_choices': [('', 'All Grades')],
                })
            }
    """
    
    checkbox_class = CheckboxInputWithEmptyValueSupport

    def __init__(self, **kwargs):
        self.checkbox_attrs = kwargs.pop('checkbox_attrs', {})
        self.extra_choices = kwargs.pop('extra_choices', ())
        super(ConfigurableCheckboxSelectMultiple, self).__init__(**kwargs)
        
    def render_checkbox(self, name, option_value, attrs,
        str_values):
        
        final_attrs = dict(attrs)
        final_attrs['check_test'] = lambda value: value in str_values
        final_attrs.update(self.checkbox_attrs)
        # Allow checkbox_attrs to override check_test
        check_test = final_attrs.pop('check_test')
        
        cb = self.checkbox_class(final_attrs, check_test)
        
        from django.utils.encoding import force_text
        option_value = force_text(option_value)
        return cb.render(name, option_value)

    list_item_template = ('<li>' +
        '<label %(label_for)s id="%(checkbox_id)s_label">' +
        '%(rendered_cb)s %(option_label)s</label></li>')
        
    def render_list_item(self, list_item_context):
        from django.utils.html import format_html
        return format_html(self.list_item_template % list_item_context)
        
    def render_item(self, index, name, option_value, option_label,
        attrs, str_values):

        from django.utils.html import format_html

        # If an ID attribute was given, add a numeric index as a suffix,
        # so that the checkboxes don't all have the same ID attribute.
        has_id = attrs and 'id' in attrs
        if has_id:
            attrs = dict(attrs, id='%s_%s' % (attrs['id'], index))
            label_for = format_html(' for="{0}"', attrs['id'])
        else:
            label_for = ''
        
        rendered_cb = self.render_checkbox(name, option_value,
            attrs, str_values)

        from django.utils.encoding import force_text
        option_label = force_text(option_label)
        
        list_item_context = {
            'checkbox_id': attrs.get('id', None),
            'label_for': label_for,
            'rendered_cb': rendered_cb,
            'name': name,
            'option_value': option_value,
            'option_label': option_label,
        }
        
        return self.render_list_item(list_item_context)
        
    def render(self, name, value, attrs=None, choices=()):
        """
        Copied and pasted from CheckboxSelectMultiple to change one
        line, adding ability to override attributes for each checkbox.
        """
        
        if value is None: value = []

        final_attrs = self.build_attrs(attrs, name=name)
        output = ['<ul>']
        # Normalize to strings
        from django.utils.encoding import force_text
        str_values = set([force_text(v) for v in value])
        
        from itertools import chain
        for i, (option_value, option_label) in enumerate(
            chain(self.extra_choices, self.choices, choices)):
            
            output.append(self.render_item(i, name, option_value,
                option_label, final_attrs, str_values))

        output.append('</ul>')

        from django.utils.safestring import mark_safe
        return mark_safe('\n'.join(output))

