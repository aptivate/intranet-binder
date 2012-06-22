"""
This file imports classes configured in settings, so that you can
refer to binder.configurable.UserModel in apps, and you'll get whatever
the developer has configured USER_MODEL as in settings.py.
"""

from django.utils.importlib import import_module
from django.utils.module_loading import module_has_submodule
from django.conf import settings

def import_class(path):
    module_name, dot, class_name = path.rpartition('.')
    module = import_module(module_name)
    return getattr(module, class_name)

UserModel = import_class(settings.USER_MODEL)
