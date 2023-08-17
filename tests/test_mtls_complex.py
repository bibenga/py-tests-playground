""" An simple example of mtls testing """

import ssl
import pytest
import trustme
from aiohttp import ClientConnectorCertificateError, ServerDisconnectedError, web


async def public(request: web.Request) -> web.Response:
    """ method without authorization """
    return web.Response(status=428)


async def secured(request: web.Request) -> web.Response:
    """ method with authorization """
    peercert = request.transport.get_extra_info("peercert")
    assert peercert is not None
    return web.Response(status=428)


async def get_client(aiohttp_client, aiohttp_server, verify_mode):
    """ create client and client ssl context """
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1", "localhost")
    client_cert = ca.issue_cert("client@127.0.0.1")

    # create server cert
    server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.configure_trust(server_ssl_context)
    server_cert.configure_cert(server_ssl_context)
    server_ssl_context.verify_mode = verify_mode

    # create client cert
    client_ssl_context = ssl.create_default_context()
    ca.configure_trust(client_ssl_context)
    client_cert.configure_cert(client_ssl_context)

    # init web application
    app = web.Application()
    app.router.add_get('/public', public)
    app.router.add_get('/secured', secured)

    # create http client
    server = await aiohttp_server(app, ssl=server_ssl_context)
    client = await aiohttp_client(server)

    return client, client_ssl_context


@pytest.mark.asyncio
async def test_https(aiohttp_client, aiohttp_server, loop):
    """test https server without client cert"""

    client, _ = await get_client(aiohttp_client, aiohttp_server, ssl.CERT_NONE)

    # connect with cert validation
    try:
        await client.get('/public')
        assert "where is an error?"
    except ClientConnectorCertificateError:
        pass

    # connect without cert validation
    resp = await client.get('/public', verify_ssl=False)
    assert resp.status == 428


@pytest.mark.asyncio
async def test_mtls(aiohttp_client, aiohttp_server, loop):
    """ test https server with client cert """

    client, client_ssl_context = await get_client(aiohttp_client, aiohttp_server, ssl.CERT_REQUIRED)

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
    resp = await client.get('/secured', ssl=client_ssl_context)
    assert resp.status == 428
