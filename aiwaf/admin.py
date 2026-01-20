from django.contrib import admin

from aiwaf.models import IPExemption, BlacklistEntry


@admin.register(BlacklistEntry)
class BlacklistEntry(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')


@admin.register(IPExemption)
class IPExemption(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'created_at')
