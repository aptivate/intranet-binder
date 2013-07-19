"""
This test runner searches for test functions matching the supplied names in
all INSTALLED_APPS, so you can launch tests like this:

    ./manage.py test test_can_create_users
    
instead of this:

    ./manage.py test binder.BinderTest.test_can_create_users

Install it by adding the following line to your settings.py:

    TEST_RUNNER = 'binder.testing.SmartTestSuiteRunner'
"""

import unittest

from django.test.simple import DjangoTestSuiteRunner

try:
    from django.test.testcases import OutputChecker, DocTestRunner
except ImportError as e:
    from django.test.simple import OutputChecker, DocTestRunner

class SmartTestSuiteRunner(DjangoTestSuiteRunner):
    def build_suite(self, test_labels, extra_tests=None, **kwargs):
        suite = unittest.TestSuite()

        if test_labels:
            for label in test_labels:
                if '.' in label:
                    from django.test.simple import build_test
                    suite.addTest(build_test(label))
                else:
                    sub_suite = self.find_tests_and_apps(label)
                    suite.addTest(sub_suite)
        else:
            from django.db.models import get_apps
            for app in get_apps():
                from django.test.simple import build_suite
                suite.addTest(build_suite(app))

        if extra_tests:
            for test in extra_tests:
                suite.addTest(test)

        try:
            from django.test.simple import reorder_suite
        except ImportError:
            from django.test.runner import reorder_suite
            
        from unittest import TestCase
        return reorder_suite(suite, (TestCase,))

    doctestOutputChecker = OutputChecker()

    def find_tests_and_apps(self, label):
        """Construct a test suite of all test methods with the specified name.
        Returns an instantiated test suite corresponding to the label provided.
        """
        
        tests = []
        from unittest import TestLoader
        loader = TestLoader()
        
        from django.db.models import get_app, get_apps
        for app_models_module in get_apps():
            app_name = app_models_module.__name__.rpartition('.')[0]
            if app_name == label:
                from django.test.simple import build_suite
                tests.append(build_suite(app_models_module))

            from django.test.simple import get_tests
            app_tests_module = get_tests(app_models_module)
            
            for sub_module in [m for m in app_models_module, app_tests_module
                if m is not None]:
                
                # print "Checking for %s in %s" % (label, sub_module)
    
                for name in dir(sub_module):
                    obj = getattr(sub_module, name)
                    import types
                    if (isinstance(obj, (type, types.ClassType)) and
                        issubclass(obj, unittest.TestCase)):
                        
                        test_names = loader.getTestCaseNames(obj)
                        # print "Checking for %s in %s.%s" % (label, obj, test_names)
                        if label in test_names:
                            tests.append(loader.loadTestsFromName(label, obj))
    
                try:
                    module = sub_module
                    from django.test import _doctest as doctest
                    
                    doctests = doctest.DocTestSuite(module,
                                                    checker=self.doctestOutputChecker,
                                                    runner=DocTestRunner)
                    # Now iterate over the suite, looking for doctests whose name
                    # matches the pattern that was given
                    for test in doctests:
                        if test._dt_test.name in (
                                '%s.%s' % (module.__name__, '.'.join(parts[1:])),
                                '%s.__test__.%s' % (module.__name__, '.'.join(parts[1:]))):
                            tests.append(test)
                except TypeError as e:
                    raise Exception("%s appears not to be a module: %s" %
                        (module, e))
                except ValueError:
                    # No doctests found.
                    pass
    
        # If no tests were found, then we were given a bad test label.
        if not tests:
            raise ValueError(("Test label '%s' does not refer to a " +
                "test method or app") % label)
    
        # Construct a suite out of the tests that matched.
        return unittest.TestSuite(tests)
