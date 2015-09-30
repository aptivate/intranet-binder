from django.contrib.auth import get_user_model
from django.conf import settings
from django.template import Context
from django.test.client import RequestFactory
from django.test.utils import override_settings
UserModel = get_user_model()

from django_dynamic_fixture import G

from test_utils import AptivateEnhancedTestCase


@override_settings(ROOT_URLCONF='intranet_binder.urls')
class BinderTest(AptivateEnhancedTestCase):
    fixtures = ['test_permissions']
    # fixtures = ['test_permissions', 'binder_test_users']

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
        import templatetags.menu as menu_tag

        context = Context({'global': {'path': '/'}})
        self.assertEqual('<td class="selected"><a href="/">Home</a></td>',
            menu_tag.menu_item(context, 'td', 'front_page', 'Home'))

        context = Context({'global': {'path': '/foo'}})
        self.assertEqual('<li ><a href="/">Home</a></li>',
            menu_tag.menu_item(context, 'li', 'front_page', 'Home'))

    def login(self, user=None):
        if user is None:
            user = G(UserModel, password=self.test_password_encrypted)
        super(BinderTest, self).login(user)

    def test_TemplatedModelChoiceField_renders_template_correctly(self):
        from admin import (TemplatedModelChoiceField,
            TemplatedModelMultipleChoiceField)

        class MockQueryset(object):
            pass

        for field_class in (
            TemplatedModelChoiceField, TemplatedModelMultipleChoiceField
        ):

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

    def fake_context(self, get_dict):
        factory = RequestFactory()
        return {
            'request': factory.get('/', data=get_dict)
        }

    def test_url_replace_templatetags_with_field_not_present(self):
        from templatetags.url_replace import url_replace
        path = url_replace(self.fake_context({'q': 'x'}), 'page', '3')
        self.assertEquals('q=x&page=3', path)

    def test_url_replace_templatetags_with_field_present(self):
        from templatetags.url_replace import url_replace
        path = url_replace(self.fake_context({'q': 'x', 'page': '1'}), 'page', '3')
        self.assertEquals('q=x&page=3', path)

    def test_ip_address_range_field_validator(self):
        from intranet_binder.modelfields import IpAddressRangeField

        def assert_valid_range(range_text):
            IpAddressRangeField().run_validators(range_text)

        assert_valid_range("1.2.3.4")
        assert_valid_range("1.2.3.0/24")
        assert_valid_range("0.0.0.0")
        assert_valid_range("0.0.0.0/0")
        assert_valid_range("0.0.0.0/32")

        def assert_invalid_range(invalid_range_text, message):
            from django.core.exceptions import ValidationError
            with self.assertRaises(ValidationError):
                IpAddressRangeField().run_validators(invalid_range_text)

        assert_invalid_range("1.2.3.4/", "missing network mask after slash")
        assert_invalid_range("0.0.0.0/-1", "negative network mask")
        assert_invalid_range("0.0.0.0/33", "excessive network mask")
        assert_invalid_range("0.0.0.0/ 32", "space before mask")
        assert_invalid_range("0.0.0.0 /32", "space before slash")
        assert_invalid_range("0.0.0.", "missing number after dot")
        assert_invalid_range("0.0.0", "missing octet")
        assert_invalid_range("0.0.0.0.", "excessive dot")
        assert_invalid_range("0.0.0.0.0", "excessive octets")
        assert_invalid_range("0.0.0. 0", "space in address")
        assert_invalid_range("0.0 0.0", "space instead of dot")
        assert_invalid_range("0.00.0.0", "double zero")
        assert_invalid_range("0.01.0.0", "leading zero")
        assert_invalid_range("0.256.0.0", "excessive octet value")
        assert_invalid_range("0.a.0.0", "letter instead of octet")
        assert_invalid_range("1.2.3.4/24", "last octet is not 0, " +
            "which conflicts with network mask")
