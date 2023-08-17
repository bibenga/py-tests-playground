""" An simple example of mtls testing """
import ssl
import trustme
from aiohttp import web


async def test_mtls_short(aiohttp_client, aiohttp_server) -> None:
    """ test https server with client cert """

    async def secured(request: web.Request) -> web.Response:
        """ method with authorization """
        peercert = request.transport.get_extra_info("peercert")
        return web.Response(status=428 if peercert is not None else 403)

    # init web application
    app = web.Application()
    app.router.add_get('/secured', secured)

    # create client and client ssl context
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    client_cert = ca.issue_cert("client@127.0.0.1", common_name="client")

    def create_ssl_context(purpose: str, ca: trustme.CA, cert: trustme.LeafCert | None) -> ssl.SSLContext:
        ctx = ssl.create_default_context(purpose)
        ca.configure_trust(ctx)
        if cert != None:
            cert.configure_cert(ctx)
        return ctx

    # create server with ssl
    server_ssl_ctx = create_ssl_context(ssl.Purpose.CLIENT_AUTH, ca, server_cert)
    server_ssl_ctx.verify_mode = ssl.CERT_OPTIONAL
    client = await aiohttp_client(await aiohttp_server(app, ssl=server_ssl_ctx))

    # connect with user client cert
    client_ssl_ctx = create_ssl_context(ssl.Purpose.SERVER_AUTH, ca, client_cert)
    resp = await client.get('/secured', ssl=client_ssl_ctx)
    assert resp.status == 428

    # connect without client cert
    client_ssl_ctx = create_ssl_context(ssl.Purpose.SERVER_AUTH, ca, None)
    resp = await client.get('/secured', ssl=client_ssl_ctx)
    assert resp.status == 403
