import datetime
from unittest import mock

import django.db
import pytest
from django.contrib.auth.models import User
from django.utils import timezone

from token_user_visit.models import TokenUserVisit, parse_remote_addr, parse_ua_string

from .utils import mock_request

ONE_DAY = datetime.timedelta(days=1)
ONE_SEC = datetime.timedelta(seconds=1)


class TestTokenUserVisitFunctions:
    @pytest.mark.parametrize(
        "xff,remote,output",
        (
            ("", "", ""),
            ("127.0.0.1", "", "127.0.0.1"),
            ("127.0.0.1,192.168.0.1", "", "127.0.0.1"),
            ("127.0.0.1", "192.168.0.1", "127.0.0.1"),
            ("", "192.168.0.1", "192.168.0.1"),
        ),
    )
    def test_remote_addr(self, xff, remote, output):
        request = mock_request()
        request.headers["X-Forwarded-For"] = xff
        request.META["REMOTE_ADDR"] = remote
        assert parse_remote_addr(request) == output

    @pytest.mark.parametrize("ua_string", ("", "Chrome"))
    def test_ua_string(self, ua_string):
        request = mock_request()
        request.headers["User-Agent"] = ua_string
        assert parse_ua_string(request) == ua_string


class TestTokenUserVisitManager:
    def test_build(self):
        request = mock_request()
        timestamp = timezone.now()
        uv = TokenUserVisit.objects.build(request, timestamp)
        assert uv.user == request.user
        assert uv.timestamp == timestamp
        assert uv.date == timestamp.date()
        assert uv.session_key == "test"
        assert uv.ua_string == "Chrome 99"
        assert uv.remote_addr == "127.0.0.1"
        assert uv.hash == uv.md5().hexdigest()
        assert uv.uuid is not None
        assert uv.pk is None

    def test_build__REQUEST_CONTEXT_EXTRACTOR(self):
        request = mock_request()
        timestamp = timezone.now()
        extractor = lambda r: {"foo": "bar"}
        with mock.patch("token_user_visit.models.REQUEST_CONTEXT_EXTRACTOR", extractor):
            uv = TokenUserVisit.objects.build(request, timestamp)
        assert uv.context == {"foo": "bar"}


class TestTokenUserVisit:

    UA_STRING = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"

    def test_user_agent(self):
        uv = TokenUserVisit(ua_string=TestTokenUserVisit.UA_STRING)
        assert str(uv.user_agent) == "PC / Mac OS X 10.15.5 / Chrome 83.0.4103"

    @pytest.mark.django_db
    def test_save(self):
        request = mock_request()
        request.user.save()
        timestamp = timezone.now()
        uv = TokenUserVisit.objects.build(request, timestamp)
        uv.hash = None
        uv.context = {"foo": "bar"}
        uv.save()
        assert uv.hash is not None
        assert uv.hash == uv.md5().hexdigest()

    @pytest.mark.django_db
    def test_unique(self):
        """Check that visits on the same day but at different times, are rejected."""
        user = User.objects.create(username="Bob")
        timestamp1 = timezone.now()
        uv1 = TokenUserVisit.objects.create(
            user=user,
            session_key="test",
            ua_string="Chrome",
            remote_addr="127.0.0.1",
            timestamp=timestamp1,
        )
        uv2 = TokenUserVisit(
            user=uv1.user,
            session_key=uv1.session_key,
            ua_string=uv1.ua_string,
            remote_addr=uv1.remote_addr,
            timestamp=uv1.timestamp - ONE_SEC,
        )
        assert uv1.date == uv2.date
        with pytest.raises(django.db.IntegrityError):
            uv2.save()

    @pytest.mark.django_db
    def test_get_latest_by(self):
        """Check that latest() is ordered by timestamp, not id."""
        user = User.objects.create(username="Bob")
        timestamp1 = timezone.now()
        uv1 = TokenUserVisit.objects.create(
            user=user,
            session_key="test",
            ua_string="Chrome",
            remote_addr="127.0.0.1",
            timestamp=timestamp1,
        )
        timestamp2 = timestamp1 - datetime.timedelta(seconds=1)
        uv2 = TokenUserVisit.objects.create(
            user=user,
            session_key="test",
            ua_string="Chrome",
            remote_addr="192.168.0.1",
            timestamp=timestamp2,
        )
        assert uv1.timestamp > uv2.timestamp
        assert user.token_user_visits.latest() == uv1

    def test_md5(self):
        """Check that MD5 changes when properties change."""
        uv = TokenUserVisit(
            user=User(),
            session_key="test",
            ua_string="Chrome",
            remote_addr="127.0.0.1",
            timestamp=timezone.now(),
        )
        h1 = uv.md5().hexdigest()
        uv.session_key = "test2"
        assert uv.md5().hexdigest() != h1
        uv.session_key = "test"

        uv.ua_string = "Chrome99"
        assert uv.md5().hexdigest() != h1
        uv.ua_string = "Chrome"

        uv.remote_addr = "192.168.0.1"
        assert uv.md5().hexdigest() != h1
        uv.remote_addr = "127.0.0.1"

        uv.user.id = 2
        assert uv.md5().hexdigest() != h1
