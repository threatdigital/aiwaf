"""
Django admin registrations for AIWAF models
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import path, reverse

from tests.base_test import AIWAFTestCase

urlpatterns = [
    path('admin/', admin.site.urls),
]


@override_settings(ROOT_URLCONF='tests.test_admin_django', MIDDLEWARE=[
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
])
class AdminRegistrationTestCase(AIWAFTestCase):

    def setUp(self):
        super().setUp()
        from aiwaf.models import DynamicKeyword, ExemptPath
        self.DynamicKeyword = DynamicKeyword
        self.ExemptPath = ExemptPath
        user = get_user_model().objects.create_superuser('admin', 'admin@example.com', 'pw')
        self.client.force_login(user)

    def test_models_registered_without_check_errors(self):
        for model in (self.ExemptPath, self.DynamicKeyword):
            self.assertIn(model, admin.site._registry)
            self.assertEqual(admin.site._registry[model].check(), [])

    def test_exempt_path_changelist(self):
        self.ExemptPath.objects.create(path='/static/', reason='assets')
        response = self.client.get(reverse('admin:aiwaf_exemptpath_changelist'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '/static/')

    def test_dynamic_keyword_changelist_and_delete(self):
        kw = self.DynamicKeyword.objects.create(keyword='assets', count=9)
        response = self.client.get(reverse('admin:aiwaf_dynamickeyword_changelist'))
        self.assertContains(response, 'assets')

        response = self.client.post(
            reverse('admin:aiwaf_dynamickeyword_delete', args=[kw.pk]), {'post': 'yes'})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.DynamicKeyword.objects.filter(pk=kw.pk).exists())
