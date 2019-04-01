def test_pywarp(fake, rp):
    email = fake.email()
    opts = rp.get_registration_options(email=email)
    print(email, opts)
