from django.contrib import admin

from .models import TokenUserVisit


class TokenUserVisitAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "user",
        "session_key",
        "token_key",
        "remote_addr",
        "user_agent",
    )
    list_filter = ("timestamp",)
    search_fields = (
        "user__first_name",
        "user__last_name",
        "user__username",
        "ua_string",
    )
    raw_id_fields = ("user",)
    readonly_fields = (
        "user",
        "hash",
        "timestamp",
        "session_key",
        "token_key",
        "remote_addr",
        "user_agent",
        "ua_string",
        "context",
        "created_at",
    )
    ordering = ("-timestamp",)


admin.site.register(TokenUserVisit, TokenUserVisitAdmin)
