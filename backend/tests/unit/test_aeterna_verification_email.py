"""The owner challenge email must show its actual server-side lifetime."""

from app.services.common.email import jinja_env


def test_verification_template_renders_supplied_lifetime() -> None:
    template = jinja_env.get_template("auth/verification.html")

    for minutes in (5, 10):
        rendered = template.render(
            first_name="Synthetic user",
            verification_code="12345678",
            expires_in_minutes=minutes,
        )
        assert f"{minutes} minutes" in rendered
