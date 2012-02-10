"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.contrib.auth.models import User
from django.conf import settings
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.template import Context

import binder.templatetags.menu as menu_tag

from models import IntranetUser, SessionWithIntranetUser
from session import SessionStore
from test_utils import AptivateEnhancedTestCase

from django.forms.forms import BoundField

def extract_fields(form):
    for fieldset in form:
        for line in fieldset:
            for field in line:
                if isinstance(field.field, BoundField):
                    yield field.field.name, field
                else:
                    yield field.field['name'], field

class BinderTest(AptivateEnhancedTestCase):
    fixtures = ['test_permissions', 'test_users']

    def setUp(self):
        AptivateEnhancedTestCase.setUp(self)
        self.john = IntranetUser.objects.get(username='john')
        self.ringo = IntranetUser.objects.get(username='ringo')

    def test_front_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        g = response.context['global']
        self.assertEqual("/", g['path'])
        self.assertEqual(settings.APP_TITLE, g['app_title'])
        
        main_menu = g['main_menu']
        self.assertEqual("Home", main_menu[0].title)
        self.assertEqual("front_page", main_menu[0].url_name)
        self.assertEqual("Documents", main_menu[1].title)
        self.assertEqual('admin:documents_document_changelist',
            main_menu[1].url_name)
        self.assertEqual("Users", main_menu[2].title)
        self.assertEqual('admin:binder_intranetuser_changelist',
            main_menu[2].url_name)
        
    def test_menu_tag_with_named_route(self):
        context = Context({'global':{'path':'/'}})
        self.assertEqual('<td class="selected"><a href="/">Home</a></td>',
            menu_tag.menu_item(context, 'front_page', 'Home'))

        context = Context({'global':{'path':'/foo'}})
        self.assertEqual('<td ><a href="/">Home</a></td>',
            menu_tag.menu_item(context, 'front_page', 'Home'))

    def login(self):
        self.assertTrue(self.client.login(username=self.ringo.username,
            password='johnpassword'), "Login failed")
        self.assertIn(settings.SESSION_COOKIE_NAME, self.client.cookies)

    def test_session_updated_by_access(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(self.client.session, SessionStore)
        
        session_record = SessionWithIntranetUser.objects.get(
            session_key=self.client.session.session_key)
        self.assertIsNone(session_record.user)
        old_date = session_record.expire_date
        
        # from binder.monkeypatch import before, breakpoint
        # before(SessionStore, 'save')(breakpoint)
        
        from time import sleep
        sleep(1) # change the current time
        
        self.login()
        session_record = SessionWithIntranetUser.objects.get(
            session_key=self.client.session.session_key)
        self.assertEqual(User.objects.get(id=self.ringo.id), session_record.user)
        self.assertNotEqual(old_date, session_record.expire_date)
        
    def test_logged_in_status_shown_in_admin_form(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_change',
            args=[self.ringo.id]))

        self.assertTrue(hasattr(response, 'context'), "Missing context " +
            "in response: %s: %s" % (response, dir(response)))
        self.assertIsNotNone(response.context, "Empty context in response: " +
            "%s: %s" % (response, dir(response)))
        self.assertIn('adminform', response.context)
        form = response.context['adminform']
        
        fields = dict(extract_fields(form))
        self.assertIn('is_logged_in', fields)
        f = fields['is_logged_in']
        self.assertEquals("True", f.contents())

    def test_logged_in_status_is_false_for_not_logged_in_user(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_change',
            args=[self.john.id]))
        self.assertIn('adminform', response.context)
        form = response.context['adminform']
        fields = dict(extract_fields(form))
        self.assertEquals("False", fields['is_logged_in'].contents())

    def test_documents_shown_in_readonly_admin_form(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_readonly',
            args=[self.john.id]))
        self.assertIn('adminform', response.context)
        form = response.context['adminform']
        fields = dict(extract_fields(form))
        self.assertIn('documents_authored', fields)
        f = fields['documents_authored']
        table = f.contents(return_table=True)
        
        from admin import DocumentsAuthoredTable
        self.assertIsInstance(table, DocumentsAuthoredTable)
        self.assertItemsEqual(self.john.document_set.all(), table.data.queryset)
