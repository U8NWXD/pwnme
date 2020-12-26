import secrets


SECRET_KEY_BITS = 256


def main():
    assert SECRET_KEY_BITS % 8 == 0
    config = {
        'SECRET_KEY': secrets.token_hex(int(SECRET_KEY_BITS / 8)),
    }
    for key, value in config.items():
        print(f'{key} = {value}')


if __name__ == '__main__':
    main()
