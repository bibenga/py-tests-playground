""" An simple example of mtls testing """
import ssl
import pytest
import trustme
from aiohttp import web


async def secured(request: web.Request) -> web.Response:
    """ method with authorization """
    peercert = request.transport.get_extra_info("peercert")
    if peercert is None:  # additional authorization can be implements
        return web.Response(status=403)
    return web.Response(status=428)


@pytest.mark.asyncio
async def test_mtls_simple(aiohttp_client, aiohttp_server, loop):
    """ test https server with client cert """

    # create client and client ssl context
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    client_cert = ca.issue_cert("client@127.0.0.1", common_name="client")

    # init web application
    app = web.Application()
    app.router.add_get('/secured', secured)

    # create server
    server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.configure_trust(server_ssl_context)
    server_cert.configure_cert(server_ssl_context)
    server_ssl_context.verify_mode = ssl.CERT_OPTIONAL
    server = await aiohttp_server(app, ssl=server_ssl_context)
    client = await aiohttp_client(server)

    # connect as user with valid cert
    client_ssl_context = ssl.create_default_context()
    ca.configure_trust(client_ssl_context)
    client_cert.configure_cert(client_ssl_context)
    resp = await client.get('/secured', ssl=client_ssl_context)
    assert resp.status == 428

    # connect as anonymous client
    anonymous_client_ssl_context = ssl.create_default_context()
    ca.configure_trust(anonymous_client_ssl_context)
    resp = await client.get('/secured', ssl=anonymous_client_ssl_context)
    assert resp.status == 403
