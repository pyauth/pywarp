def test_get_registration_options(fake, rp):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

    user = opts['user']
    assert user['name'] == email

    display_name = fake.name()
    icon = fake.image_url()
    opts = rp.get_registration_options(
        email=email, display_name=display_name, icon=icon
    )

    user = opts['user']
    assert user['name'] == email
    assert user['displayName'] == display_name
    assert user['icon'] == icon
