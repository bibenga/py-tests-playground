""" An simple example of mtls testing """

from dataclasses import dataclass
import ssl
import pytest
import trustme
from aiohttp import ClientConnectorCertificateError, ServerDisconnectedError, web


@pytest.fixture
async def app() -> web.Application:
    """ demo application """

    async def public(_request: web.Request) -> web.Response:
        """ method without authorization """
        return web.Response(status=428)

    async def secured(request: web.Request) -> web.Response:
        """ method with authorization """
        peercert = request.transport.get_extra_info("peercert")
        if peercert is None:  # additional authorization can be implements
            return web.Response(status=403)
        return web.Response(status=428)

    app = web.Application()
    app.router.add_get('/public', public)
    app.router.add_get('/secured', secured)
    return app


@dataclass
class SslTestCfg:
    """SSL configuration for tests"""
    ca: trustme.CA
    server_cert: trustme.LeafCert
    client_cert: trustme.LeafCert
    server_ssl: ssl.SSLContext
    anon_ssl: ssl.SSLContext
    user_ssl: ssl.SSLContext


@pytest.fixture
def ssl_cfg() -> SslTestCfg:
    """ create ssl configuration for test """

    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1", "localhost")
    client_cert = ca.issue_cert("client@127.0.0.1")

    server_ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.configure_trust(server_ssl)
    server_cert.configure_cert(server_ssl)

    # create context for server validation
    anon_ssl = ssl.create_default_context()
    ca.configure_trust(anon_ssl)

    # create context with client certificate and server validation
    user_ssl = ssl.create_default_context()
    ca.configure_trust(user_ssl)
    client_cert.configure_cert(user_ssl)

    return SslTestCfg(
        ca=ca,
        server_cert=server_cert,
        client_cert=client_cert,
        server_ssl=server_ssl,
        anon_ssl=anon_ssl,
        user_ssl=user_ssl,
    )


async def test_https(ssl_cfg: SslTestCfg, app: web.Application, aiohttp_client, aiohttp_server) -> None:
    """test https server without client cert"""

    # create http client
    ssl_cfg.server_ssl.verify_mode = ssl.CERT_NONE
    server = await aiohttp_server(app, ssl=ssl_cfg.server_ssl)
    client = await aiohttp_client(server)

    # connect with cert validation
    try:
        await client.get('/public')
        assert "where is an error?"
    except ClientConnectorCertificateError:
        pass

    # connect with ca
    resp = await client.get('/public', ssl=ssl_cfg.anon_ssl)
    assert resp.status == 428

    # connect without cert validation
    resp = await client.get('/public', verify_ssl=False)
    assert resp.status == 428


async def test_mtls_required(ssl_cfg: SslTestCfg, app: web.Application, aiohttp_client, aiohttp_server) -> None:
    """ test https server with client cert and server require certeficate """

    # create http client
    ssl_cfg.server_ssl.verify_mode = ssl.CERT_REQUIRED
    server = await aiohttp_server(app, ssl=ssl_cfg.server_ssl)
    client = await aiohttp_client(server)

    # connect without client cert but with cert validation
    try:
        await client.get('/secured', verify_ssl=True)
        assert "where is an error?"
    except ClientConnectorCertificateError:
        # a connection should failed
        pass

    # connect without client cert but without cert validation
    try:
        await client.get('/secured', verify_ssl=False)
        assert "where is an error?"
    except ServerDisconnectedError:
        # a connection should failed
        pass

    # connect with client cert
    resp = await client.get('/secured', ssl=ssl_cfg.user_ssl)
    assert resp.status == 428


async def test_mtls_optional(ssl_cfg: SslTestCfg, app: web.Application, aiohttp_client, aiohttp_server) -> None:
    """ test https server with client cert and server can accept certeficate """

    ssl_cfg.server_ssl.verify_mode = ssl.CERT_OPTIONAL
    server = await aiohttp_server(app, ssl=ssl_cfg.server_ssl)
    client = await aiohttp_client(server)

    # connect as anonymous client
    resp = await client.get('/secured', ssl=ssl_cfg.anon_ssl)
    assert resp.status == 403

    # connect as user with valid cert
    resp = await client.get('/secured', ssl=ssl_cfg.user_ssl)
    assert resp.status == 428
