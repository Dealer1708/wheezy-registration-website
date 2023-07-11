from wheezy.template.engine import Engine
from wheezy.template.loader import FileLoader
from wheezy.template.ext.core import CoreExtension
from wheezy.web.templates import WheezyTemplate
from wheezy.html.utils import html_escape
from wheezy.html.ext.template import WidgetExtension


options = {}

searchpath = ["templates"]
engine = Engine(
    loader=FileLoader(searchpath),
    extensions=[
        CoreExtension(),
        WidgetExtension(),
    ],
)
engine.global_vars.update({"h": html_escape})
options.update({
    'render_template': WheezyTemplate(engine)
})
