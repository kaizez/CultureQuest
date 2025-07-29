import re

# Regular Expressions for Validation
NAME_REGEX = r'^[A-Za-z\s]+$'  # Only letters and spaces
PHONE_REGEX = r'^[0-9]+$'  # Only digits

def validate_name(name):
    """Validate the name field."""
    return re.match(NAME_REGEX, name)

def validate_phone(phone):
    """Validate the phone field."""
    return re.match(PHONE_REGEX, phone)
