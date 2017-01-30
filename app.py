import web
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

urls = (r'/', 'IndexPage',
        r'/attrs/', 'AttrsPage',
        r'/metadata/', 'MetadataPage')

app = web.application(urls, globals())

if web.config.get('_session') is None:
    store = web.session.DiskStore('sessions')
    session = web.session.Session(app, store, initializer={})
    web.config._session = session
else:
    session = web.config._session

templates = web.template.render("./templates", globals={},  base='base')

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path='./saml')
    return auth

class IndexPage:
    def GET(self):
        return self.load_page()

    def POST(self):
        return self.load_page()

    def load_page(self):
        req = prepare_request()
        auth = init_saml_auth(req)
        errors = []
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False

        input_data = web.input()

        if 'sso' in input_data:
            raise web.seeother(auth.login())
        elif 'sso2' in input_data:
            return_to = web.ctx.homepath + '/attrs/'
            raise web.seeother(auth.login(return_to))
        elif 'slo' in input_data:
            name_id = None
            session_index = None
            if 'samlNameId' in session:
                name_id = session['samlNameId']
            if 'samlSessionIndex' in session:
                session_index = session['samlSessionIndex']

            raise web.seeother(auth.logout(name_id=name_id, session_index=session_index))
        elif 'acs' in input_data:
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                session['samlUserdata'] = auth.get_attributes()
                session['samlNameId'] = auth.get_nameid()
                session['samlSessionIndex'] = auth.get_session_index()
                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                if 'RelayState' in input_data and self_url != input_data['RelayState']:
                    raise web.seeother(auth.redirect_to(input_data['RelayState']))
        elif 'sls' in input_data:
            dscb = lambda: session.clear()
            url = auth.process_slo(delete_session_cb=dscb)
            errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return web.seeother(url)
                else:
                    success_slo = True

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        return templates.index(
            errors=errors,
            not_auth_warn=not_auth_warn,
            success_slo=success_slo,
            attributes=attributes,
            paint_logout=paint_logout
        )

class AttrsPage:
    def GET(self):
        paint_logout = False
        attributes = False

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        return templates.attrs(paint_logout=paint_logout,
                            attributes=attributes)


def prepare_request():
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    data = web.input()
    return {
        'https': 'on' if web.ctx.protocol == 'https' else 'off',
        'http_host': web.ctx.environ["SERVER_NAME"],
        'server_port': web.ctx.environ["SERVER_PORT"],
        'script_name': web.ctx.homepath,
        'get_data': data.copy(),
        'post_data': data.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': web.ctx.query
    }

class MetadataPage:
    def GET(self):
        req = prepare_request()
        auth = init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            web.header('Content-Type', 'text/xml')
            return metadata
        else:
            web.ctx.status = "500 Internal Server Error"
            return ', '.join(errors)

if __name__ == "__main__":
    app.run()
