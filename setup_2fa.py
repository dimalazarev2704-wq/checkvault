"""Run once. Scan the QR code with an authenticator app (Google Authenticator, Authy, 1Password...)."""
import pyotp

secret = pyotp.random_base32()
uri = pyotp.TOTP(secret).provisioning_uri(name="CheckVault", issuer_name="CheckVault")

try:
    import qrcode
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.print_ascii(invert=True)
except ImportError:
    print("Install qrcode for a scannable code, or type the secret into your app by hand.")

print("\nSecret (also enter this by hand if the QR won't scan):", secret)
print('\nThen run:  export TOTP_SECRET="%s"' % secret)
print("Keep this secret private and back it up, the same way as your encryption key.")
