"""
Template tags for dealing with lists of items and formatting them.

For example, see the search.html.django template, which does this:

    Your search for {{ form.q.value }} did not match 
                    
    {% if form.get_models %}
        any
        {% load lists %}
        {{ form.get_models|format_items:"item._meta.verbose_name_plural.title"|join_last_two:" or "|join:", " }}.
    {% else %}
        anything.
    {% endif %}
    
What this does:

* form.get_models returns a list of Model classes. e.g. [Document, Person]
* if the list is empty, we write "... did not match anything"
* otherwise, we format each item as "item._meta.verbose_name_plural.title"
  which returns the verbose_name_plural of the Model, and
* join the last two with the word "or", e.g. ["Quotes", "Documents or People"]
* join all the rest with commas, replacing the list with a simple string,
  e.g. "Quotes, Documents or People"
"""

from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()

from django.utils.text import unescape_string_literal
from django.utils.safestring import mark_safe

import django.template.base
from django.template.base import Variable, VARIABLE_ATTRIBUTE_SEPARATOR

class VariableWithUnderscoresAllowed(Variable):
    """
    If we write the templates, we get to decide what's allowed, including
    _meta. kthxbye.
    """

    def __init__(self, var):
        self.var = var
        self.literal = None
        self.lookups = None
        self.translate = False

        try:
            # First try to treat this variable as a number.
            #
            # Note that this could cause an OverflowError here that we're not
            # catching. Since this should only happen at compile time, that's
            # probably OK.
            self.literal = float(var)

            # So it's a float... is it an int? If the original value contained a
            # dot or an "e" then it was a float, not an int.
            if '.' not in var and 'e' not in var.lower():
                self.literal = int(self.literal)

            # "2." is invalid
            if var.endswith('.'):
                raise ValueError

        except ValueError:
            # A ValueError means that the variable isn't a number.
            if var.startswith('_(') and var.endswith(')'):
                # The result of the lookup should be translated at rendering
                # time.
                self.translate = True
                var = var[2:-1]
            # If it's wrapped with quotes (single or double), then
            # we're also dealing with a literal.
            try:
                self.literal = mark_safe(unescape_string_literal(var))
            except ValueError:
                # Otherwise we'll set self.lookups so that resolve() knows we're
                # dealing with a bonafide variable
                self.lookups = tuple(var.split(VARIABLE_ATTRIBUTE_SEPARATOR))

@register.filter
def format_items(items, template_string):
    """
    Formats the items in a list using the Django Template syntax.
    
    The template_string is used as a template to control the output.
    For example, you can render a certain property of each item in the
    list using "item.full_name" as your template The {{ }} braces will be
    added automatically, as they are not legal inside a template tag.
    
    In the context used to render the template, "item" is the current item 
    and nothing else is available.
    """

    from django.template import Template
    django.template.base.Variable = VariableWithUnderscoresAllowed
    template = Template("{{ %s }}" % template_string)
    django.template.base.Variable = Variable

    from django.template import Context

    result = []
    for item in items:
        result.append(template.render(Context({'item': item})))

    return result

@register.filter
def join_last_two(items, final_separator):
    """
    Joins the last two items in a list with the specified separator.
    If the list contains zero or one items, nothing is changed.
    """

    if len(items) < 2:
        return items
    
    items[-2:] = (final_separator.join(items[-2:]),)
    return items

@register.filter
def if_empty_list(items, new_sole_item_if_empty):
    """
    Joins the last two items in a list with the specified separator.
    If the list contains zero or one items, nothing is changed.
    """

    if len(items) == 0:
        return [new_sole_item_if_empty]

    return items
