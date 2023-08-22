from wheezy.web.handlers import BaseHandler


class MainHandler(BaseHandler):
    def authorize_model(self, model, template, valid_result):
        if type(valid_result) is Exception:
            self.errors = {'errors': valid_result}

            return self.render_response(
                template_name=template,
                model=model
            )
        self.principal = valid_result

        return self.redirect_for("home")