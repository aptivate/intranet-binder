from django.db import models

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

from django.conf import settings
if 'south' in settings.INSTALLED_APPS:
    from south.modelsinspector import add_introspection_rules
    import re
    add_introspection_rules([], ["^%s\.ManyToManyField$" % re.escape(ManyToManyField.__module__)])
