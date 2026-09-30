from django.contrib import admin

from aiwaf.models import (
    IPExemption, BlacklistEntry, GeoBlockedCountry, ExemptPath, DynamicKeyword,
)


@admin.register(BlacklistEntry)
class BlacklistEntryAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')
    search_fields = ('ip_address',)
    date_hierarchy = 'created_at'


@admin.register(IPExemption)
class IPExemptionAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')
    search_fields = ('ip_address',)
    date_hierarchy = 'created_at'


@admin.register(GeoBlockedCountry)
class GeoBlockedCountryAdmin(admin.ModelAdmin):
    list_display = ('country_code', 'reason', 'created_at')


@admin.register(ExemptPath)
class ExemptPathAdmin(admin.ModelAdmin):
    list_display = ('path', 'enabled', 'reason', 'updated_at')
    list_editable = ('enabled',)
    list_filter = ('enabled',)
    search_fields = ('path', 'reason')


@admin.register(DynamicKeyword)
class DynamicKeywordAdmin(admin.ModelAdmin):
    list_display = ('keyword', 'count', 'last_updated')
    search_fields = ('keyword',)
    date_hierarchy = 'last_updated'
