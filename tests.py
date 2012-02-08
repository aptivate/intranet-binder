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

class BinderTest(AptivateEnhancedTestCase):
    fixtures = ['test_permissions', 'test_users']

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
        self.assertTrue(self.client.login(username=self.john.username,
            password='johnpassword'), "Login failed")
        self.assertIn(settings.SESSION_COOKIE_NAME, self.client.cookies)
         
        """
        print "session cookie = %s" % (
            self.client.cookies[django_settings.SESSION_COOKIE_NAME])
        """

    def test_session_updated_by_access(self):
        self.john = IntranetUser.objects.get(username='john')

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
        self.assertEqual(User.objects.get(id=self.john.id), session_record.user)
        self.assertNotEqual(old_date, session_record.expire_date)