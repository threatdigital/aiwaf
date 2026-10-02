#!/usr/bin/env python3
"""
Django tests for the per-process exempt-IP / exempt-path cache.
"""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from tests.base_test import AIWAFTestCase
from aiwaf import storage
from aiwaf.models import ExemptPath, IPExemption
from aiwaf.utils import get_exempt_paths, is_exempt_path, is_ip_exempted


@override_settings(AIWAF_EXEMPT_IPS=[], AIWAF_EXEMPT_PATHS=[])
class ExemptionCacheTestCase(AIWAFTestCase):
    def test_repeat_lookups_do_not_query(self):
        IPExemption.objects.create(ip_address="203.0.113.1")
        ExemptPath.objects.create(path="/cached/")
        self.assertTrue(is_ip_exempted("203.0.113.1"))
        self.assertTrue(is_exempt_path("/cached/x/"))

        with CaptureQueriesContext(connection) as ctx:
            for _ in range(5):
                self.assertTrue(is_ip_exempted("203.0.113.1"))
                self.assertFalse(is_ip_exempted("203.0.113.2"))
                self.assertTrue(is_exempt_path("/cached/x/"))
                self.assertFalse(is_exempt_path("/other/"))
        self.assertEqual(len(ctx.captured_queries), 0)

    def test_save_and_delete_clear_the_cache(self):
        self.assertFalse(is_ip_exempted("203.0.113.3"))
        self.assertNotIn("/new/", get_exempt_paths())

        exemption = IPExemption.objects.create(ip_address="203.0.113.3")
        path = ExemptPath.objects.create(path="/new/")
        self.assertTrue(is_ip_exempted("203.0.113.3"))
        self.assertIn("/new/", get_exempt_paths())

        path.enabled = False
        path.save()
        self.assertNotIn("/new/", get_exempt_paths())

        exemption.delete()
        self.assertFalse(is_ip_exempted("203.0.113.3"))

    def test_queryset_delete_clears_the_cache(self):
        # the store's remove_exemption / clear_all go through QuerySet.delete
        IPExemption.objects.create(ip_address="203.0.113.4")
        self.assertTrue(is_ip_exempted("203.0.113.4"))
        storage.get_exemption_store().clear_all()
        self.assertFalse(is_ip_exempted("203.0.113.4"))

    def test_unsignalled_change_waits_for_ttl(self):
        IPExemption.objects.create(ip_address="203.0.113.5")
        self.assertTrue(is_ip_exempted("203.0.113.5"))

        # .update() sends no signal, so only the TTL picks it up
        IPExemption.objects.filter(ip_address="203.0.113.5").update(ip_address="203.0.113.6")
        self.assertTrue(is_ip_exempted("203.0.113.5"))

        later = storage.time.monotonic() + 61
        with patch.object(storage.time, "monotonic", return_value=later):
            self.assertFalse(is_ip_exempted("203.0.113.5"))
            self.assertTrue(is_ip_exempted("203.0.113.6"))

    @override_settings(AIWAF_EXEMPTION_CACHE_TTL=0)
    def test_ttl_zero_disables_the_cache(self):
        IPExemption.objects.create(ip_address="203.0.113.7")
        with CaptureQueriesContext(connection) as ctx:
            self.assertTrue(is_ip_exempted("203.0.113.7"))
            self.assertTrue(is_ip_exempted("203.0.113.7"))
        self.assertEqual(len(ctx.captured_queries), 2)

    def test_clear_during_load_is_not_overwritten(self):
        IPExemption.objects.create(ip_address="203.0.113.8")
        real_loader = storage._load_exempt_ips

        def loader_with_concurrent_edit():
            value = real_loader()
            storage.clear_exemption_cache()  # an edit lands mid-load
            return value

        with patch.object(storage, "_load_exempt_ips", loader_with_concurrent_edit):
            self.assertTrue(is_ip_exempted("203.0.113.8"))
        self.assertNotIn("ips", storage._exemption_cache)

    def test_ipv6_lookup_is_normalized(self):
        IPExemption.objects.create(ip_address="2001:db8::1")
        self.assertTrue(is_ip_exempted("2001:DB8:0:0:0:0:0:1"))

    def test_load_failure_is_not_exempt_and_not_cached(self):
        with patch.object(storage, "_load_exempt_ips", side_effect=RuntimeError("db down")):
            self.assertFalse(is_ip_exempted("203.0.113.9"))
        self.assertNotIn("ips", storage._exemption_cache)
