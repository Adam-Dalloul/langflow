from lfx.custom.custom_component.component import Component
from lfx.inputs.inputs import StrInput
from lfx.schema.message import Message
from lfx.template.field.base import Output
from lfx.utils.env_var_security import is_protected_env_var, safe_getenv


class GetEnvVar(Component):
    display_name = "Get Environment Variable"
    description = "Gets the value of an environment variable from the system."
    icon = "AstraDB"
    legacy = True

    inputs = [
        StrInput(
            name="env_var_name",
            display_name="Environment Variable Name",
            info="Name of the environment variable to get",
        )
    ]

    outputs = [
        Output(display_name="Environment Variable Value", name="env_var_value", method="process_inputs"),
    ]

    def process_inputs(self) -> Message:
        # env_var_name is tenant-controlled: refuse server-reserved/infrastructure secrets
        # (LANGFLOW_SECRET_KEY, DATABASE_URL, AWS_*, ...) so this component cannot be used to
        # exfiltrate the host's own secrets in a multi-tenant deployment.
        if is_protected_env_var(self.env_var_name):
            msg = f"Environment variable {self.env_var_name} is not accessible for security reasons"
            raise ValueError(msg)
        value = safe_getenv(self.env_var_name)
        if value is None:
            msg = f"Environment variable {self.env_var_name} not set"
            raise ValueError(msg)
        return Message(text=value)
