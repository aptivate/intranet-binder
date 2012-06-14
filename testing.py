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
from django.test.testcases import OutputChecker

class SmartTestSuiteRunner(DjangoTestSuiteRunner):
    def build_suite(self, test_labels, extra_tests=None, **kwargs):
        suite = unittest.TestSuite()

        if test_labels:
            for label in test_labels:
                if '.' in label:
                    suite.addTest(build_test(label))
                else:
                    sub_suite = self.find_tests_and_apps(label)
                    suite.addTest(sub_suite)
        else:
            from django.db.models import get_apps
            for app in get_apps():
                suite.addTest(build_suite(app))

        if extra_tests:
            for test in extra_tests:
                suite.addTest(test)

        from django.test.simple import reorder_suite
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
            from django.test.simple import get_tests
            app_tests_module = get_tests(app_models_module)
            
            for app_module in [m for m in app_models_module, app_tests_module
                if m is not None]:
                
                # print "Checking for %s in %s" % (label, app_module)
    
                if app_module.__name__ == label:
                    from django.test.simple import build_suite
                    tests.append(build_suite(app_module))
                
                for name in dir(app_module):
                    obj = getattr(app_module, name)
                    import types
                    if (isinstance(obj, (type, types.ClassType)) and
                        issubclass(obj, unittest.TestCase)):
                        
                        test_names = loader.getTestCaseNames(obj)
                        # print "Checking for %s in %s.%s" % (label, obj, test_names)
                        if label in test_names:
                            tests.append(loader.loadTestsFromName(label, obj))
    
                try:
                    module = app_module
                    from django.test import _doctest as doctest
                    from django.test.testcases import DocTestRunner
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
            raise ValueError("Test label '%s' does not refer to a test" % label)
    
        # Construct a suite out of the tests that matched.
        return unittest.TestSuite(tests)
