import django.db.models

import binder.templatetags.menu as menu_tag

from django.contrib.auth.models import User, Group
from django.conf import settings
from django.core.urlresolvers import reverse
from django.template import Context

from models import IntranetUser, SessionWithIntranetUser
from session import SessionStore
from test_utils import AptivateEnhancedTestCase

from binder.views import FrontPageView

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
        
    def test_logged_in_status_shown_in_admin_form(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_change',
            args=[self.ringo.id]))

        self.assertEqual("True", self.extract_admin_form_field(response, 
            'is_logged_in').contents())

    def test_logged_in_status_is_false_for_not_logged_in_user(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_change',
            args=[self.john.id]))

        self.assertEqual("False", self.extract_admin_form_field(response, 
            'is_logged_in').contents())

    def test_documents_shown_in_readonly_admin_form(self):
        self.login()
        response = self.client.get(reverse('admin:binder_intranetuser_readonly',
            args=[self.john.id]))
        table = self.extract_admin_form_field(response, 
            'documents_authored').contents(return_table=True)
        
        from admin import DocumentsAuthoredTable
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
    
    def assert_redirect_not_form_error(self, response):
        if not response.redirect_chain:
            # this probably means that the form was not saved properly, and 
            # we have a context to look at for errors
            form = response.context['profile_form']
            self.assertDictEqual({}, form.errors, "form should not have errors")
    
    def test_profile_photo_upload(self):
        self.login(self.ringo)
        response = self.client.get(reverse('user_profile'))
        form = response.context['profile_form']

        from django.forms import fields as form_fields
        self.assertIsInstance(form.base_fields['photo'], form_fields.ImageField) 
        self.assertTrue(form.is_multipart, "Must be a multipart form " +
            "to allow file uploads")
        
        import os
        f = open(os.path.join(os.path.dirname(__file__), 'fixtures',
            'transparent.gif'))
        # setattr(f, 'name', 'transparent.gif')
        
        response = self.client.post(reverse('user_profile'),
            self.update_form_values(form, photo=f), follow=True)
        
        self.assert_redirect_not_form_error(response)
         
        url = response.real_request.build_absolute_uri(reverse('front_page'))
        self.assertSequenceEqual([(url, 302)], response.redirect_chain,
            "saving profile should have caused a redirect: %s" % 
            response.content)
        
        new_ringo = IntranetUser.objects.get(id=self.ringo.id)
        self.assertEqual('profile_photos/transparent.gif', new_ringo.photo.name)

    def assert_password_change_fails(self, new_password, confirmation,
        **expected_errors):
        
        response = self.client.get(reverse('user_profile'))
        form = response.context['profile_form']
        new_values = self.update_form_values(form, password1=new_password,
            password2=confirmation)
        
        response = self.client.post(reverse('user_profile'), new_values,
            follow=True)
        self.assertListEqual([], response.redirect_chain,
            "POST should have failed with a password mismatch.")
        
        form = response.context['profile_form']
        self.assertDictEqual(expected_errors, form.errors)
        
    def test_change_password_using_profile_page(self):
        self.login(self.ringo)
        
        response = self.client.get(reverse('user_profile'))
        form = response.context['profile_form']
        self.assertIn('password1', form.fields)
        self.assertIn('password2', form.fields)
        
        from password import PasswordChangeMixin
        self.assertIsInstance(form, PasswordChangeMixin)

        from views import UserProfileForm        
        
        # leaving both fields blank does not change the password
        response = self.client.post(reverse('user_profile'),
            self.update_form_values(form, password1='', password2=''),
            follow=True)
        self.assert_redirect_not_form_error(response)
        new_ringo = IntranetUser.objects.get(id=self.ringo.id)
        self.assertEqual(self.ringo.password, new_ringo.password)
        
        # setting one requires the other to be set to the same value
        self.assert_password_change_fails('', 'bar',
            password1=[UserProfileForm.COMPLETE_BOTH])
        self.assert_password_change_fails('foo', '',
            password2=[UserProfileForm.COMPLETE_BOTH])
        self.assert_password_change_fails('foo', 'bar',
            password2=[UserProfileForm.MISMATCH])

        response = self.client.get(reverse('user_profile'))
        form = response.context['profile_form']

        response = self.client.post(reverse('user_profile'),
            self.update_form_values(form, password1='foo', password2='foo'),
            follow=True)
        self.assert_redirect_not_form_error(response)
        
        new_ringo = IntranetUser.objects.get(id=self.ringo.id)
        self.assertTrue(new_ringo.check_password('foo'),
            "password should have changed")
    
    # disabled until thumbnail support is added
    """
    def test_can_create_user_profile_form(self):
        from views import UserProfileForm
        
        # test without any photo, should not crash
        form = UserProfileForm()
        self.assertNotEqual("", form.as_table())
        
        # test with photo, should generate a thumbnail
        from django.db.models.fields.files import FieldFile
        self.assertIsInstance(form['photo'], FieldFile) 
                import os
        f = open(os.path.join(os.path.dirname(__file__), 'fixtures',
            'transparent.gif'))
        # setattr(f, 'name', 'transparent.gif')
        
        response = self.client.post(reverse('user_profile'),
            self.update_form_values(form, photo=f), follow=True)
    
    def test_valid_results_returned_from_ldap_database(self):
        from auth import ActiveDirectoryBackend
        backend = ActiveDirectoryBackend()
        conn = backend.get_connection("chris2", "testing")
        
        import ldap
        from django.conf import settings
        results = conn.search_ext_s(settings.AD_SEARCH_DN, ldap.SCOPE_SUBTREE, 
            "objectClass=user", settings.AD_SEARCH_FIELDS)
        conn.unbind_s()

        print ("%s" % str(results[244]))
    """

    def test_user_profile_form_required_attribute(self):
        from views import UserProfileForm
        form = UserProfileForm()
        self.assertEqual("required", form.required_css_class)
    
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
    
    def test_date_joined_field_is_separated_from_the_django_one(self):
        date_joined_nondjango = IntranetUser._meta.get_field('date_joined_nondjango')
        import django.db.models.fields
        self.assertIsInstance(date_joined_nondjango,
            django.db.models.fields.DateField)
        self.assertTrue(date_joined_nondjango.blank)
        self.assertTrue(date_joined_nondjango.null)
        
        from admin import IntranetUserAdmin
        self.assertIn('date_joined', IntranetUserAdmin.exclude)
        
        from views import UserProfileForm
        self.assertIn('date_joined', UserProfileForm._meta.exclude)
        self.assertNotIn('date_joined', UserProfileForm.base_fields)
        self.assertIn('date_joined_nondjango', UserProfileForm.base_fields)
        
        from django.contrib.admin.widgets import AdminDateWidget
        self.assertIsInstance(
            UserProfileForm.base_fields['date_joined_nondjango'].widget,
            AdminDateWidget, "Date Joined widget should be a calendar control")

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
        self.assertEqual(UserModel._meta.verbose_name_plural, 
            user_menu_item.title,
            "Wrong title in menu item %s" % (user_menu_item,))
