from django.db import models
from django.utils.translation import ugettext_lazy as _

# from http://stackoverflow.com/questions/2350681/django-lowercasecharfield
class ModifyingFieldDescriptor(object):
    """ Modifies a field when set using the field's (overriden) .to_python() method. """
    def __init__(self, field):
        self.field = field
    def __get__(self, instance, owner=None):
        if instance is None:
            raise AttributeError('Can only be accessed via an instance.')
        return instance.__dict__[self.field.name]
    def __set__(self, instance, value):
        instance.__dict__[self.field.name] = self.field.to_python(value)

class LowerCaseCharField(models.CharField):
    def to_python(self, value):
        value = super(LowerCaseCharField, self).to_python(value)
        if isinstance(value, basestring):
            return value.lower()
        return value
    def contribute_to_class(self, cls, name):
        super(LowerCaseCharField, self).contribute_to_class(cls, name)
        setattr(cls, self.name, ModifyingFieldDescriptor(self))

# Try to work around a problem with cross-database associations.
from django.db.models.fields import related
from django.utils.functional import cached_property

class PatchedReverseManyRelatedObjectsDescriptor(related.ReverseManyRelatedObjectsDescriptor):
    @cached_property
    def related_manager_cls(self):
        # Dynamically create a class that subclasses the related model's
        # default manager.
        superclass = self.field.rel.to._default_manager.__class__
        dynamic_class = super(PatchedReverseManyRelatedObjectsDescriptor,
            self).related_manager_cls
        field = self.field

        def replacement_get_query_set(self):
            try:
                return self.instance._prefetched_objects_cache[self.prefetch_cache_name]
            except (AttributeError, KeyError):
                from django.db import router

                # original version:
                db = self._db or router.db_for_read(self.instance.__class__, instance=self.instance)

                # patched replacement:
                # db = self._db or router.db_for_read(field.rel.to)

                # import pdb; pdb.set_trace()
                qs = CustomQuerySet(self.model, using=db) # self._db)
                qs.using(db)._next_is_sticky().filter(**self.core_filters)
                qs.field = field
                return qs

                # return superclass.get_query_set(self).using(db)._next_is_sticky().filter(**self.core_filters)

        dynamic_class.get_query_set = replacement_get_query_set
        return dynamic_class

from django.db.models.query import QuerySet
class CustomQuerySet(QuerySet):
    def values_list(self, *fields, **kwargs):
        # import pdb; pdb.set_trace()

        if len(fields) == 1 and fields[0] == 'pk':
            # we should answer this query using only the join table,
            # so that it doesn't crash if the target table is not
            # in the same database as the source and join tables.

            # self.query = self.query.clone()
            # self.query.tables = [self.field.m2m_db_table()]
            # fields = [self.field.m2m_reverse_name()]

            from django.db.models.sql.query import Query
            self.query = Query(self.field.rel.through)
            fields = [self.field.m2m_reverse_field_name()]

        return super(CustomQuerySet, self).values_list(*fields, **kwargs)

class ManyToManyField(related.ManyToManyField):
    def __init__(self, to, **kwargs):
    	"""
    	Undo the annoying non-optional help text added by parent class:
    	'Hold down "Control", or "Command" on a Mac, to select more than one.'
    	"""
    	old_help_text = kwargs.get('help_text', '')
    	super(ManyToManyField, self).__init__(to, **kwargs)
    	self.help_text = old_help_text

    def contribute_to_class(self, cls, name):
    	super(ManyToManyField, self).contribute_to_class(cls, name)
        # Add the descriptor for the m2m relation, using our patched
        # ReverseManyRelatedObjectsDescriptor
        setattr(cls, self.name, PatchedReverseManyRelatedObjectsDescriptor(self))

class ManyToManyWithBlankForAll(ManyToManyField):
    """
    A version of ManyToManyField where a blank value is interpreted as
    meaning "all" instead of "none". This is mainly an exercise/example
    in customising the text displayed for the blank choice at the top
    of the list, so that it works with checkbox sets, etc.
    """

    def __init__(self, to, blank_choice=None, **kwargs):
        super(ManyToManyWithBlankForAll, self).__init__(to,
            blank=True, **kwargs)
        if blank_choice is None:
            blank_choice = "All %s" % to._meta.verbose_name_plural
        self.blank_choice = blank_choice

    def get_choices(self, include_blank=True):
        import pdb; pdb.set_trace()
        return super(ManyToManyWithBlankForAll, self).get_choices(
            include_blank=True, blank_choice=(('', self.blank_choice),))

    def _get_choices(self):
        import pdb; pdb.set_trace()
        """
        from itertools import chain
        return chain((('', self.blank_choice),),
            super(ManyToManyWithBlankForAll, self).get_choices())
        """
        return super(ManyToManyWithBlankForAll, self)._get_choices()

    def _set_choices(self, choices):
        import pdb; pdb.set_trace()
        """
        from itertools import chain
        return chain((('', self.blank_choice),),
            super(ManyToManyWithBlankForAll, self).get_choices())
        """
        return super(ManyToManyWithBlankForAll, self)._set_choices(choices)

    choices = property(_get_choices, _set_choices)

import re
IP_ADDRESS_BYTE_REGEX = r'(0|[1-9][0-9]{0,2})'
IP_ADDRESS_REGEX = (
    '(?x)^' +
    IP_ADDRESS_BYTE_REGEX + r'\.' +
    IP_ADDRESS_BYTE_REGEX + r'\.' +
    IP_ADDRESS_BYTE_REGEX + r'\.' +
    IP_ADDRESS_BYTE_REGEX +
    '(?:/' + IP_ADDRESS_BYTE_REGEX + ')?$')

class IpAddressRangeValidator(object):
    def __init__(self, message="Invalid IP address range", code="invalid",
        regex=IP_ADDRESS_REGEX):

        self.message = message
        self.code = code

        # Compile the regex if it was not passed pre-compiled.
        self.regex_string = regex
        from django.utils import six
        if isinstance(regex, six.string_types):
            regex = re.compile(regex)
        self.regex = regex

    def __call__(self, value):
        """
        Validates that the input matches the regular expression.
        """
        from django.utils.encoding import force_text
        from django.core.exceptions import ValidationError

        matches = self.regex.match(force_text(value))
        if matches is None:
            raise ValidationError(("%s: does not match the pattern: " +
                "a.b.c.d or a.b.c.d/e") % self.message, code=self.code)

        ip_bits = long(0)

        for i in range(4):
            octet = int(matches.group(i + 1))
            if octet >= 0 and octet <= 255:
                ip_bits <<= 8
                ip_bits |= octet
            else:
                raise ValidationError(("%s: address byte %d (%s) " +
                    "must be between 0 and 255") %
                    (self.message, i, octet), code=self.code)

        if matches.group(5) is None:
            # it's allowed to omit the mask length completely
            mask_len = 32
        else:
            mask_len = int(matches.group(5))

        if mask_len < 0 or mask_len > 32:
            raise ValidationError(("%s: network mask length %s " +
                "should be between 0 and 32") %
                (self.message, matches.group(5)), code=self.code)

        mask = (long(1) << (32 - mask_len)) - 1
        masked_value = (ip_bits & mask)
        if masked_value != 0:
            raise ValidationError(("%s: according to the network mask %d, " +
                "the last %d bits should be 0, but they are %d instead. " +
                "Please check the address and mask") %
                (self.message, mask_len, 32 - mask_len, masked_value),
                code=self.code)

from django.db.models.fields import Field
class IpAddressRangeField(Field):
    description = _("IPv4 address and network mask (CIDR)")

    def __init__(self, validators=[], *args, **kwargs):
        kwargs['max_length'] = 15

        validators.append(IpAddressRangeValidator())
        super(IpAddressRangeField, self).__init__(validators=validators,
            *args, **kwargs)

    """
    def validate(self, value, model_instance):
        import pdb; pdb.set_trace()
        super(IpAddressRangeField, self).validate(value, model_instance)
    """

from django.conf import settings
if 'south' in settings.INSTALLED_APPS:
    from south.modelsinspector import add_introspection_rules
    import re
    module_regexp = re.escape(ManyToManyField.__module__)
    add_introspection_rules([], ["^%s\.ManyToManyField$" % module_regexp])
    add_introspection_rules([], ["^%s\.IpAddressRangeField" % module_regexp])
    add_introspection_rules([], ["^%s\.LowerCaseCharField" % module_regexp])
