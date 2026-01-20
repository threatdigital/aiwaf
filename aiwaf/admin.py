from django.contrib import admin

from aiwaf.models import IPExemption, BlacklistEntry, GeoBlockedCountry


@admin.register(BlacklistEntry)
class BlacklistEntryAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')


@admin.register(IPExemption)
class IPExemptionAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')


@admin.register(GeoBlockedCountry)
class GeoBlockedCountryAdmin(admin.ModelAdmin):
    list_display = ('country_code', 'reason', 'created_at')
