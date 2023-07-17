import logging
import typing

import django.db
from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from token_user_visit.models import TokenUserVisit

from .settings import (
    ACTIVATE_SESSION_ONLY_RECORDING,
    DUPLICATE_LOG_LEVEL,
    RECORDING_BYPASS,
    RECORDING_DISABLED,
)

logger = logging.getLogger(__name__)


@django.db.transaction.atomic
def save_user_visit(user_visit: TokenUserVisit) -> None:
    """Save the user visit and handle db.IntegrityError."""
    try:
        user_visit.save()
    except django.db.IntegrityError:
        getattr(logger, DUPLICATE_LOG_LEVEL)(
            "Error saving user visit (hash='%s')", user_visit.hash
        )


class TokenUserVisitMiddleware:
    """Middleware to record user visits."""

    def __init__(self, get_response: typing.Callable) -> None:
        if RECORDING_DISABLED:
            raise MiddlewareNotUsed("TokenUserVisit recording has been disabled")
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> typing.Optional[HttpResponse]:
        if RECORDING_BYPASS(request):
            return self.get_response(request)

        if request.META.get("HTTP_AUTHORIZATION", "").startswith(
            "Bearer"
        ) and not ACTIVATE_SESSION_ONLY_RECORDING(request):
            uv = TokenUserVisit.objects.build_with_token(request, timezone.now())

        elif request.user.is_anonymous:
            return self.get_response(request)

        elif request.session.session_key is not None:
            uv = TokenUserVisit.objects.build_with_session(request, timezone.now())

        else:
            getattr(logger, "warning")(
                f"Error creating user visit. No token or session for user: \
                {request.user}"
            )
            return self.get_response(request)

        if not TokenUserVisit.objects.filter(hash=uv.hash).exists():
            save_user_visit(uv)

        return self.get_response(request)
