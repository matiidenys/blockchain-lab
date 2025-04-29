import time
import uuid
from database import connect_db
from crypto_utils import hash_data_keccak256, sign_data_rsa
from user import get_private_key # Імпортуємо функцію отримання приватного ключа

def create_transaction(sender_id: str, recipient_id: str, amount: float):
    # 1. Створюємо базовий запис транзакції
    transaction_uuid = str(uuid.uuid4())
    timestamp = int(time.time())

    # Для першої транзакції BlockChainHash та Nonce з BlockChainTable дорівнюють 0
    blockchain_hash_from_block = "0" * 64
    nonce_from_block = 0

    transaction_data = {
        'TAID': transaction_uuid,
        'TADate': timestamp,
        'From': sender_id,
        'To': recipient_id,
        'TASUM': amount,
        'Nonce': 0,
        'TAApproved': False,
        'TAssign': None,
        'TAHash': None
    }

    # 2. Формуємо дані для хешування
    data_string_to_hash = (
        str(transaction_data['TAID']) +
        str(transaction_data['TADate']) +
        str(transaction_data['From']) +
        str(transaction_data['To']) +
        str(transaction_data['TASUM']) +
        str(blockchain_hash_from_block) +
        str(nonce_from_block)
    )

    # 3. Обчислюємо хеш транзакції
    transaction_hash = hash_data_keccak256(data_string_to_hash.encode('utf-8'))
    transaction_data['TAHash'] = transaction_hash

    # 4. Отримуємо приватний ключ відправника та підписуємо хеш транзакції
    sender_private_key = get_private_key(sender_id)

    if sender_private_key:
        signature_bytes = sign_data_rsa(sender_private_key, transaction_hash.encode('utf-8'))
        transaction_data['TAssign'] = signature_bytes.hex()
        print(f"Транзакцію {transaction_data['TAID']} підписано відправником {sender_id}.")
        return transaction_data # Повертаємо підписану транзакцію
    else:
        print(f"Помилка: Не вдалося отримати приватний ключ для відправника {sender_id}. Транзакцію не підписано.")
        return None


def save_transaction(transaction_data: dict):

    # Зберігає об'єкт транзакції у колекції Transactions та оновлює баланси гаманців.

    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних.")
        return False

    # Перевірка наявності всіх необхідних полів перед обробкою
    required_fields = ['TAID', 'From', 'To', 'TASUM', 'TAHash', 'TAssign']
    if not all(field in transaction_data and transaction_data[field] is not None for field in required_fields):
        print("Помилка: Недостатньо даних для збереження або обробки транзакції.")
        return False

    sender_id = transaction_data['From']
    amount = transaction_data['TASUM']

    # 1. Перевірка балансу відправника
    sender_wallet = db.EWallet.find_one({'CNUCoinID': sender_id})

    if sender_wallet is None:
        print(f"Помилка: Гаманець відправника {sender_id} не знайдено.")
        return False

    if sender_wallet['Balance'] < amount:
        print(f"Помилка: Недостатньо коштів у відправника {sender_id} для здійснення транзакції.")
        return False

    # 2. Збереження транзакції у колекції Transactions
    try:
        result = db.Transactions.insert_one(transaction_data)
        print(f"Транзакцію {transaction_data['TAID']} успішно збережено.")
        return result.inserted_id  # Повертаємо ID збереженої транзакції
    except Exception as e:
        print(f"Помилка при збереженні транзакції: {e}")
        return False


# Приклад використання:
if __name__ == "__main__":
    sender_real_id = "bcef5c9a92a1e2a00173be08d4abddd65b018232c395ac32ad7a0c49801aa375"
    recipient_real_id = "011c8aa9e79970c0846d9bda2f9c09d42a83ba805efb2a86d341686584b7249b"
    amount_to_send = 4.4 # Сума транзакції

    print(f"Створення та обробка транзакції від {sender_real_id} до {recipient_real_id} на суму {amount_to_send}")

    # 1. Створюємо та підписуємо транзакцію
    signed_transaction = create_transaction(sender_real_id, recipient_real_id, amount_to_send)

    if signed_transaction:
        print("\nСтворено та підписано об'єкт транзакції. Спроба збереження та оновлення балансів.")
        # 2. Зберігаємо підписану транзакцію та оновлюємо баланси
        saved_transaction_id = save_transaction(signed_transaction)

        if saved_transaction_id:
            print(f"\nТранзакцію з ID {saved_transaction_id} успішно збережено.")
        else:
            print("\nНе вдалося обробити транзакцію (зберегти).")
    else:
        print("Не вдалося створити або підписати транзакцію.")