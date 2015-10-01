from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def url_get_params_replace(context, field, value):
    """ The idea here is to take a GET dict and replace one value in the
    GET dict (or create it if it doesn't exist) and then return the encoded
    value.  Useful for pagination.

    From http://stackoverflow.com/a/16609498/3189
    """
    get_dict = context['request'].GET.copy()
    get_dict[field] = value
    return get_dict.urlencode()
