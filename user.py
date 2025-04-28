from database import connect_db # Імпортуємо функцію підключення до БД
# Імпортуємо функції для генерації ключів, серіалізації, хешування та завантаження ключів з crypto_utils
from crypto_utils import generate_rsa_keys, serialize_public_key, serialize_private_key, hash_data_keccak256, load_private_key_from_pem

def register_user(is_miner=False):
    # Реєструє нового користувача у системі CNUCoin.
    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних.")
        return None

    # 1. Генеруємо ключі
    private_key, public_key = generate_rsa_keys()
    pub_pem_bytes = serialize_public_key(public_key) # Отримуємо байти публічного ключа
    priv_pem_bytes = serialize_private_key(private_key) # Отримуємо байти приватного ключа

    # 2. Генеруємо ідентифікатор користувача за допомогою Keccak-256
    user_id = hash_data_keccak256(pub_pem_bytes) # Передаємо байти

    # Перевіряємо, чи користувач з таким ID вже існує
    if db.CnuCoinMembers.find_one({'CNUCoinID': user_id}):
        print(f"Користувач з ID {user_id} вже існує. Спробуйте ще раз.")
        return None

    # 3. Зберігаємо дані у колекціях

    # Зберігаємо дані в CnuCoinMembers (публічна інформація)
    member_data = {
        'CNUCoinID': user_id,
        'PublicKey': pub_pem_bytes.decode('utf-8'), # Зберігаємо як рядок для зручності
        'IsMiner': is_miner
    }
    db.CnuCoinMembers.insert_one(member_data)
    print(f"Користувача {user_id} додано до CnuCoinMembers.")

    # Зберігаємо приватний ключ (приватна інформація)
    private_data = {
        'CNUCoinID': user_id,
        'PrivateKey': priv_pem_bytes.decode('utf-8'), # Зберігаємо як рядок для зручності
        'PublicKey': pub_pem_bytes.decode('utf-8') # Можна також зберігати публічний ключ тут для зручності
    }
    db.Private.insert_one(private_data)
    print(f"Приватний ключ користувача {user_id} збережено у Private колекції.")

    # Створюємо запис в EWallet (електронний гаманець)
    # При реєстрації додаємо початкову суму
    initial_balance = 100
    ewallet_data = {
        'CNUCoinID': user_id,
        'Balance': initial_balance
    }
    db.EWallet.insert_one(ewallet_data)
    print(f"Електронний гаманець для користувача {user_id} створено з балансом {initial_balance}.")


    print(f"\nКористувача {user_id} успішно зареєстровано.")
    return user_id

# Функція для отримання приватного ключа
def get_private_key(user_id: str):
    # Отримуємо приватний ключ користувача (як об'єкт ключа) з бази даних.
    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних для отримання приватного ключа.")
        return None

    try:
        # Знаходимо документ з приватним ключем за CNUCoinID користувача
        private_data = db.Private.find_one({'CNUCoinID': user_id})

        if private_data and 'PrivateKey' in private_data:
            # Отримуємо приватний ключ у форматі рядка PEM
            priv_pem_string = private_data['PrivateKey']
            # Перетворюємо рядок PEM назад у байти
            priv_pem_bytes = priv_pem_string.encode('utf-8')
            # Завантажуємо об'єкт приватного ключа за допомогою виправленої функції з crypto_utils
            private_key_object = load_private_key_from_pem(priv_pem_bytes)
            return private_key_object
        else:
            print(f"Приватний ключ для користувача {user_id} не знайдено.")
            return None
    except Exception as e:
        print(f"Помилка при отриманні приватного ключа: {e}")
        return None


# Приклад використання:
if __name__ == "__main__":
    # # Зареєструємо кількох користувачів
    # print("Реєстрація Користувача 1:")
    # user1_id = register_user(is_miner=False)
    #
    # print("\nРеєстрація Користувача 2:")
    # user2_id = register_user(is_miner=True) # Зареєструємо одного як майнера
    #
    # print("\nРеєстрація Користувача 3:")
    # user3_id = register_user()

    # Перевірка правильності витягування приватного ключа
    user_private_key = serialize_private_key(get_private_key("011c8aa9e79970c0846d9bda2f9c09d42a83ba805efb2a86d341686584b7249b")).decode("utf-8")
    print(user_private_key)