# inject secret into robot suite.. doing this via python
# to ensure this can also run in older robot versions
# tests related 
try:
    from robot.api.types import Secret
    SECRET_PASSWORD = Secret("passwd")
except (ImportError, ModuleNotFoundError):
    SECRET_PASSWORD = "not-supported"
