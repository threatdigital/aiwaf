from django.apps import AppConfig

class AiwafConfig(AppConfig):
    name = "aiwaf"
    verbose_name = "AI‑Driven Web Application Firewall"

    def ready(self):
        from django.db.models.signals import post_delete, post_save
        from .models import ExemptPath, IPExemption
        from .storage import exemption_changed

        # keep the per-process exemption cache in step with edits
        for model in (IPExemption, ExemptPath):
            for name, signal in (("save", post_save), ("delete", post_delete)):
                signal.connect(
                    exemption_changed,
                    sender=model,
                    dispatch_uid=f"aiwaf_exemption_cache_{name}_{model.__name__}",
                )

        try:
            from .settings_compat import apply_legacy_settings
            apply_legacy_settings()
        except Exception:
            pass
