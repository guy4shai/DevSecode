# ⚠️ This file contains intentionally hardcoded secrets for testing secret scanning tools.

# --- Cloud Providers ---
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

gcp_api_key = "AIzaSyA-FAKEKEYFOR-TESTING1234567890"
azure_storage_key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDZQz1hldEXAMPLEKEY=="

# --- GitHub and GitLab Tokens ---
gitlab_token = "glpat-12345678abcdefgHijKLMNOPqrstu"

# --- Slack and Discord Webhooks ---
slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
discord_webhook = "https://discord.com/api/webhooks/1234567890/ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# --- Database Credentials ---
db_user = "admin"
db_password = "P@ssw0rd!"
mysql_uri = "mysql://admin:P@ssw0rd!@localhost:3306/testdb"
postgres_uri = "postgresql://admin:admin123@localhost:5432/exampledb"

# --- Stripe and PayPal Keys ---
stripe_secret_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
paypal_client_secret = "EAFakeClientSecret1234567890"

# --- API Keys for Common Services ---
sendgrid_api_key = "SG.fake_api_key_for_testing_purpose"
twilio_auth_token = "1234567890abcdef1234567890abcdef"
algolia_api_key = "1234567890abcdef1234567890abcdef"

# --- JWT and SSH Private Keys ---
jwt_secret = "myjwtsecret1234567890"
private_ssh_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzY4QWEXAMPLEFAKEKEYFORTESTONLY28F8Z1ER1dZf
-----END RSA PRIVATE KEY-----
"""

print("This file is full of test secrets. Do not use in production.")

