import django.db.models

import templatetags.menu as menu_tag

from django.contrib.auth.models import User, Group
from django.conf import settings
from django.core.urlresolvers import reverse
from django.template import Context

from models import IntranetUser, SessionWithIntranetUser
from session import SessionStore
from test_utils import AptivateEnhancedTestCase

from views import FrontPageView

class BinderTest(AptivateEnhancedTestCase):
    fixtures = ['test_programs', 'test_permissions', 'test_users']

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

    def test_menu_tag_with_named_route(self):
        context = Context({'global':{'path':'/'}})
        self.assertEqual('<td class="selected"><a href="/">Home</a></td>',
            menu_tag.menu_item(context, 'td', 'front_page', 'Home'))

        context = Context({'global':{'path':'/foo'}})
        self.assertEqual('<li ><a href="/">Home</a></li>',
            menu_tag.menu_item(context, 'li', 'front_page', 'Home'))

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

    def assert_logged_in_status_field(self, user, expected_value):
        response = self.client.get(reverse('admin:binder_intranetuser_change',
            args=[user.id]))

        self.assertEqual(str(expected_value),
            self.extract_admin_form_field(response,  'is_logged_in').contents())

        response = self.client.get(reverse('admin:binder_intranetuser_readonly',
            args=[user.id]))

        self.assertEqual(expected_value, 
            self.extract_admin_form(response).form['is_logged_in'].readonly())
                
    def test_logged_in_status_shown_in_admin_form(self):
        self.login()
        self.assertTrue(self.current_user.is_logged_in())
        self.assert_logged_in_status_field(self.current_user, True)

        self.assertNotEqual(self.john, self.current_user)
        self.assert_logged_in_status_field(self.john, False)
        
        previous_user = self.current_user
        response = self.client.get(reverse('logout'))
        self.assertEqual(200, response.status_code)
        self.assertEqual('Logged out', response.context['title'])
        self.assertFalse(previous_user.is_logged_in())

    def test_documents_shown_in_readonly_admin_form(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_readonly',
            args=[self.john.id]))
        table = self.extract_admin_form_field(response, 
            'documents_authored').contents(return_table=True)
        
        from widgets import DocumentsAuthoredTable
        self.assertIsInstance(table, DocumentsAuthoredTable)
        self.assertItemsEqual(self.john.documents_authored.all(), 
            table.data.queryset)
    
    def test_profile_picture_shown_in_user_admin_and_profile_forms(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_readonly',
            args=[self.john.id]))
        field = self.extract_admin_form_field(response, 'photo')
        
        from widgets import AdminImageWidgetWithThumbnail
        widget = field.form.fields['photo'].widget
        self.assertIsInstance(widget, AdminImageWidgetWithThumbnail)

        response = self.client.get(reverse('admin:binder_intranetuser_change',
            args=[self.john.id]))
        field = self.extract_admin_form_field(response, 'photo')
        widget = field.field.field.widget
        self.assertIsInstance(widget, AdminImageWidgetWithThumbnail)
        
        response = self.client.get(reverse('user_profile'))
        form = self.assertInDict('profile_form', response.context)
        field = self.assertInDict('photo', form.fields)
        self.assertIsInstance(field.widget, AdminImageWidgetWithThumbnail)
        
    def test_notes_field_for_user(self):
        self.assertIsInstance(IntranetUser._meta.get_field('notes'),
            django.db.models.TextField)

    def test_ordinary_user_cannot_change_self_to_superuser(self):
        self.login(self.john)
        response = self.client.get(reverse('user_profile'))
        self.assertIn('profile_form', response.context, "Where's my form? " +
            "Am I really logged in?\n" + response.content)

        form = self.assertInDict('profile_form', response.context)
        data = self.update_form_values(form)
        data['full_name'] = "Wheee"
        data['is_superuser'] = True
        
        # import pdb; pdb.set_trace()
        
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
    
    def test_adding_user_to_administrators_group_sets_superuser_flag(self):
        from models import IntranetGroup 
        manager = IntranetGroup.objects.get(name="Manager")
        user = IntranetGroup.objects.get(name="User")
        self.assertTrue(manager.administrators, """This test will not work 
            unless the Manager group's administrators flag is set""")
        
        self.assertFalse(self.john.is_superuser)
        self.assertNotIn(manager, self.john.groups.all(),
            "This test will not work if john is in the Manager group")
        
        self.john.groups = [manager]
        self.john.save()
        self.assertTrue(self.john.is_superuser)

        self.john.groups = [manager]
        self.john.save()
        self.assertTrue(self.john.is_superuser)

        self.john.groups = [user]
        self.john.save()
        self.assertFalse(self.john.is_superuser)
        
    def test_admin_form_should_stop_user_demoting_themselves(self):
        self.login()
        
        from models import IntranetGroup 
        manager = IntranetGroup.objects.get(name="Manager")
        self.assertTrue(manager.administrators, """This test will not work 
            unless the Manager group's administrators flag is set""")
        self.assertTrue(self.current_user.is_superuser)
        self.assertIn(manager.group, self.current_user.groups.all())

        url = reverse('admin:binder_intranetuser_change',
            args=[self.current_user.id])
        response = self.client.get(url)

        # POST without changing anything should be fine
        form = self.assertInDict('adminform', response.context).form
        new_values = self.update_form_values(form)
        response = self.client.post(url, new_values, follow=True)
        self.assert_changelist_not_admin_form_with_errors(response)

        # but changing the group should result in an error
        user = IntranetGroup.objects.get(name="User")
        new_values = self.update_form_values(form, groups=[user.pk])
        response = self.client.post(url, new_values)
        self.assert_admin_form_with_errors_not_changelist(response,
            {'groups': ['You cannot demote yourself from the %s group' %
                manager.name]})
        
        # shouldn't be allowed to do anything that removes our superuser flag
        # remove us from manager group, but keep superuser flag.
        # temporarily disable the signal listener so that it doesn't
        # automatically demote us from superuser
        from django.db.models.signals import m2m_changed
        from django.dispatch import receiver
        m2m_changed.disconnect(sender=User.groups.through,
            receiver=IntranetUser.groups_changed, dispatch_uid="User_groups_changed")
        self.current_user.groups = [user]
        m2m_changed.connect(sender=User.groups.through,
            receiver=IntranetUser.groups_changed, dispatch_uid="User_groups_changed")
        
        self.current_user = self.current_user.reload()
        self.assertItemsEqual([user.group], self.current_user.groups.all())
        self.assertTrue(self.current_user.is_superuser)
        # now we're not removing ourselves from any groups, but saving
        # would still demote us automatically from being a superuser.
        response = self.client.post(url, new_values)
        self.assert_admin_form_with_errors_not_changelist(response,
            {'groups': ['You cannot demote yourself from being a superuser. ' +
                'You must put yourself in one of the Administrators groups: ' +
                '%s' % IntranetGroup.objects.filter(administrators=True)]})
        
        # we shouldn't be allowed to delete ourselves either
        deleted = IntranetGroup.objects.get(name="Deleted")
        user = IntranetGroup.objects.get(name="User")
        new_values = self.update_form_values(form, groups=[manager.pk, deleted.pk])
        # import pdb; pdb.set_trace()
        response = self.client.post(url, new_values)
        self.assert_admin_form_with_errors_not_changelist(response,
            {'groups': ['You cannot place yourself in the %s group' %
                deleted.name]})
        
    def test_admin_form_should_allow_user_to_promote_and_demote_others(self):
        self.login()
        
        from models import IntranetGroup 
        manager = IntranetGroup.objects.get(name="Manager")
        self.assertTrue(manager.administrators, """This test will not work 
            unless the Manager group's administrators flag is set""")

        self.assertIn(manager.group, self.current_user.groups.all())
        self.assertTrue(self.current_user.is_manager)
        self.assertTrue(self.current_user.is_superuser)
        
        self.assertNotIn(manager.group, self.john.groups.all())
        self.assertFalse(self.john.is_manager)
        self.assertFalse(self.john.is_superuser)

        url = reverse('admin:binder_intranetuser_change',
            args=[self.john.id])
        response = self.client.get(url)

        form = self.assertInDict('adminform', response.context).form
        new_values = self.update_form_values(form, groups=[manager.pk])
        response = self.client.post(url, new_values, follow=True)
        self.assert_changelist_not_admin_form_with_errors(response)
        self.assertTrue(self.john.reload().is_superuser)

        user = IntranetGroup.objects.get(name="User")
        new_values = self.update_form_values(form, groups=[user.pk])
        response = self.client.post(url, new_values, follow=True)
        self.assert_changelist_not_admin_form_with_errors(response)
        self.assertFalse(self.john.reload().is_superuser)

        # import pdb; pdb.set_trace()
        self.assertTrue(self.john.reload().is_active,
            "test precondition failed")
        deleted = IntranetGroup.objects.get(inactive=True)
        new_values = self.update_form_values(form, groups=[deleted.pk])
        response = self.client.post(url, new_values, follow=True)
        self.assert_changelist_not_admin_form_with_errors(response)
        self.assertFalse(self.john.reload().is_active)

    def test_can_create_users(self):
        u = IntranetUser(username="max")
        u.save()

        self.login()
        
        from models import IntranetGroup 
        manager = IntranetGroup.objects.get(name="Manager")
        self.assertTrue(manager.administrators, """This test will not work 
            unless the Manager group's administrators flag is set""")

        self.assertIn(manager.group, self.current_user.groups.all())
        self.assertTrue(self.current_user.is_manager)
        self.assertTrue(self.current_user.is_superuser)
        
        url = reverse('admin:binder_intranetuser_add')
        response = self.client.get(url)

        form = self.assertInDict('adminform', response.context).form
        # import pdb; pdb.set_trace()
        self.assertNotIn('is_active', form.fields)
        self.assertNotIn('is_staff', form.fields)
        self.assertNotIn('is_superuser', form.fields)
        
        values = dict(username="stevie", groups=[manager.pk])
        # enter some random value for all required fields
        for field in form:
            if field.field.required and field.name not in values:
                # import pdb; pdb.set_trace()
                from django.forms.fields import ChoiceField
                
                db_field = form._meta.model._meta.get_field(field.name)
                from django.db.models.fields import DateTimeField
                
                if isinstance(field.field, ChoiceField): 
                    values[field.name] = field.field.choices[1][0]
                elif isinstance(db_field, DateTimeField):
                    from datetime import datetime
                    values[field.name] = datetime.now()
                else:
                    values[field.name] = "blarg"
        
        params = self.update_form_values(form, **values)
        response = self.client.post(url, params, follow=True)
        self.assert_changelist_not_admin_form_with_errors(response)
        stevie = IntranetUser.objects.get(username="stevie")
        self.assertTrue(stevie.is_active)
        self.assertTrue(stevie.is_staff)
        self.assertTrue(stevie.is_superuser)
    
    def test_create_user_with_photo_and_missing_required_fields(self):
        self.login()
        url = reverse('admin:binder_intranetuser_add')
        response = self.client.get(url)

        form = self.assertInDict('adminform', response.context).form
        # import pdb; pdb.set_trace()
        
        import os
        f = open(os.path.join(os.path.dirname(__file__), 'fixtures',
            'transparent.gif'))
        # setattr(f, 'name', 'transparent.gif')
        
        params = self.update_form_values(form, photo=f)
        response = self.client.post(url, params, follow=True)
        self.assert_admin_form_with_errors_not_changelist(response)
    
    def test_menu_contains_correct_user_model(self):
        """
        Even if the administrator has replaced the main menu with a custom
        one in their application, the default main menu (from the binder app)
        should still contain a link to the user manager for whatever the
        configured user model is.
        """
        
        self.login()
        self.assertTrue(self.current_user.is_manager)
        
        from binder.main_menu import MainMenu
        menu = MainMenu(self.fake_login_request)
        
        from configurable import UserModel
        user_changelist = ('admin:%s_%s_changelist' %
            (UserModel._meta.app_label, UserModel._meta.module_name))
        
        user_menu_item = [i for i in menu.generators 
            if i.url_name == user_changelist][0]
        from django.utils.text import capfirst
        self.assertEqual(capfirst(UserModel._meta.verbose_name_plural), 
            user_menu_item.title,
            "Wrong title in menu item %s" % (user_menu_item,))

    def test_TemplatedModelChoiceField_renders_template_correctly(self):
        from configurable import UserModel
        from admin import (TemplatedModelChoiceField,
            TemplatedModelMultipleChoiceField)
        
        class MockQueryset(object):
            pass
        
        for field_class in (TemplatedModelChoiceField,
            TemplatedModelMultipleChoiceField):
            
            field = field_class(queryset=MockQueryset(),
                template='{{ obj.full_name }},{{ field.context.bonk }},{{context.bonk}}',
                context={'bonk': 'Bonk!'})
    
            fake_object = {'full_name': 'whee'}         
            self.assertEqual('whee,Bonk!,Bonk!', 
                field.label_from_instance(fake_object))

            # check that the default template is sensible
            field = field_class(queryset=MockQueryset(),
                context={'bonk': 'Bonk!'})

            from django.template import Template
            self.assertEqual(Template('{{ obj }}'), field.template)
    
            fake_object = {'full_name': 'whee'}         
            self.assertEqual("{&#39;full_name&#39;: &#39;whee&#39;}", 
                field.label_from_instance(fake_object))

    def test_lists_templatetags_format_items(self):
        from templatetags.lists import format_items
        
        from django.contrib.auth.models import User, Group
        
        self.assertEquals([m._meta.verbose_name_plural.title() for m in []],
            format_items([], "item._meta.verbose_name_plural.title"))
        self.assertEquals([m._meta.verbose_name_plural.title() for m in [User]],
            format_items([User], "item._meta.verbose_name_plural.title"))
        self.assertEquals([m._meta.verbose_name_plural.title() for m in [User, Group]],
            format_items([User, Group], "item._meta.verbose_name_plural.title"))

    def test_lists_templatetags_join_last_two(self):
        from templatetags.lists import join_last_two
        
        self.assertEquals([],
            join_last_two([], " whee "))
        self.assertEquals(["a"],
            join_last_two(["a"], " whee "))
        self.assertEquals(["a whee b"],
            join_last_two(["a", "b"], " whee "))
        self.assertEquals(["a", "b whee c"],
            join_last_two(["a", "b", "c"], " whee "))

    def test_lists_templatetags_if_empty_list(self):
        from templatetags.lists import if_empty_list
        
        self.assertEquals(["nada"],
            if_empty_list([], "nada"))
        self.assertEquals(["a"],
            if_empty_list(["a"], "nada"))
        self.assertEquals(["a", "b"],
            if_empty_list(["a", "b"], "nada"))
