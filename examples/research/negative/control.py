"""Text resembling a sink should not be treated as executable syntax."""
DOCUMENTATION = "eval(request.body) and pickle.loads(request.body) are review leads"


def evaluate(value):
    return value
