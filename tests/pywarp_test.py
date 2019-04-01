def test_get_registration_options(fake, rp):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

    user = opts['user']
    assert user['name'] == email
