from django import template
# until we upgrade to django 1.4, use the backported template library:

# from binder.backports import template

register = template.Library()

# https://docs.djangoproject.com/en/dev/howto/custom-template-tags/#assignment-tags
# @register.assignment_tag(takes_context=True)
@register.simple_tag(takes_context=True)
def submit_buttons(context):
    """
    Return the context variables needed to populate the admin change form
    submit buttons.
    
    Changed to add a variable to the context, instead of rendering a
    hard-coded template, to allow easy extension (adding buttons)
    entirely within the template system.
    
    You can create a new template in one of the paths searched by
    ModelAdmin.render_change_form. Make it extend admin/change_form.html,
    which comes from the binder app instead of the Django admin system, and
    contains a block called submit_buttons that uses this template tag
    to add variables to the context.
    
    You can override that submit_buttons block to contain whatever buttons
    you want.
    """
    
    from django.contrib.admin.templatetags import admin_modify
    context['buttons'] = admin_modify.submit_row(context)
    return ""