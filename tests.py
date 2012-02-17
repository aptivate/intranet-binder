import django.db.models

import binder.templatetags.menu as menu_tag

from django.contrib.auth.models import User, Group
from django.conf import settings
from django.core.urlresolvers import reverse
from django.template import Context

from models import IntranetUser, SessionWithIntranetUser
from session import SessionStore
from test_utils import AptivateEnhancedTestCase

from django.forms.forms import BoundField
from binder.views import FrontPageView

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

    def test_front_page_without_login(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        g = response.context['global']
        self.assertEqual("/", g['path'])
        self.assertEqual(settings.APP_TITLE, g['app_title'])
        
    def test_menu_without_login(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        g = response.context['global']
        
        main_menu = g['main_menu']
        self.assertSequenceEqual([
            ("Home", "front_page"),
            ], [(item.title, item.url_name) for item in main_menu],
            "Wrong main menu for unauthenticated users")

    def test_menu_with_login_as_normal_user(self):
        self.login(self.john)
        
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        g = response.context['global']
        
        main_menu = g['main_menu']
        self.assertSequenceEqual([
            ("Home", "front_page"),
            ("Documents", "admin:documents_document_changelist"),
            ], [(item.title, item.url_name) for item in main_menu],
            "Wrong main menu for ordinary users")

    def test_menu_with_login_as_manager(self):
        self.login(self.ringo)
        
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        g = response.context['global']
        
        main_menu = g['main_menu']
        self.assertSequenceEqual([
            ("Home", "front_page"),
            ("Documents", "admin:documents_document_changelist"),
            ("Users", "admin:binder_intranetuser_changelist"),
            ("Admin", "admin:index"),
            ], [(item.title, item.url_name) for item in main_menu],
            "Wrong main menu for ordinary users")
        
    def test_menu_tag_with_named_route(self):
        context = Context({'global':{'path':'/'}})
        self.assertEqual('<td class="selected"><a href="/">Home</a></td>',
            menu_tag.menu_item(context, 'front_page', 'Home'))

        context = Context({'global':{'path':'/foo'}})
        self.assertEqual('<td ><a href="/">Home</a></td>',
            menu_tag.menu_item(context, 'front_page', 'Home'))

    def login(self, user=None):
        if user is None:
            user = self.ringo
        super(BinderTest, self).login(user)

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
        
    def test_notes_field_for_user(self):
        self.assertIsInstance(IntranetUser._meta.get_field('notes'),
            django.db.models.TextField)

    def test_ordinary_user_cannot_change_self_to_superuser(self):
        self.login(self.john)
        response = self.client.get(reverse('user_profile'))
        self.assertIn('profile_form', response.context, "Where's my form?" +
            "Am I really logged in?\n" + response.content)

        form = response.context['profile_form']
        # self.assertTrue(form.is_valid(), str(form.errors))
        data = dict(form.initial)
        data['full_name'] = "Wheee"
        data['is_superuser'] = True
        
        response = self.client.post(reverse('user_profile'), data=data,
            follow=True)

        if ('profile_form' in response.context):
            # should not happen, implies a form validation error?
            form = response.context['profile_form']
            self.assertItemsEqual([], form.errors,
                "form should not have errors")
        
        self.assertTemplateUsed(response, FrontPageView.template_name,
            'profile page should redirect to front page on success: ' +
            '%s' % response)

        new_john = IntranetUser.objects.get(id=self.john.id)
        self.assertFalse(new_john.is_superuser)
        self.assertEqual("Wheee", new_john.full_name)
        