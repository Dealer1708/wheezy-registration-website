from wheezy.template.engine import Engine
from wheezy.template.loader import FileLoader
from wheezy.template.ext.core import CoreExtension
from wheezy.web.templates import WheezyTemplate
from wheezy.html.utils import html_escape
from wheezy.html.ext.template import WidgetExtension
from wheezy.security.crypto import Ticket


engine = Engine(
    loader=FileLoader(["templates"]),
    extensions=[
        CoreExtension(),
        WidgetExtension(),
    ],
)
engine.global_vars.update({"h": html_escape})
options = {
    'render_template': WheezyTemplate(engine),
    'CRYPTO_VALIDATION_KEY': 'oLm9uLjCAxVkBece7XHpMKbg1',
    'CRYPTO_ENCRYPTION_KEY': 'kwHt89N3HYGB54o2BSTVyxief'
}

ticket = Ticket(
    max_age=15 * 60,
    salt="p2e9gKZoqau9DWS3tq16CkCvaFLozxgsyeu",
    options=options
)

roles = [
    'admin',
    'user',
    'gamer',
    'super'
]
roles = list(dict.fromkeys(roles))