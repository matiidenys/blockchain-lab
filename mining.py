from database import connect_db
from crypto_utils import hash_data_keccak256, sign_data_rsa
from user import get_private_key
import time

def get_latest_blockchain_data():
    """
    Отримує дані останнього блоку з колекції BlockChain.
    Для першого блоку повертає нульові значення.
    """
    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних для отримання останнього блоку.")
        return None

    try:
        # Шукаємо останній блок, сортуючи за ID документа в порядку спадання.
        latest_block = db.BlockChain.find_one(sort=[('_id', -1)])

        if latest_block:
            print("Отримано дані останнього блоку.")
            # Повертаємо потрібні поля
            return {
                '_id': latest_block.get('_id'), # Додамо ID документа блоку
                'BlockChainHash': latest_block.get('BlockChainHash', "0" * 64),
                'Nonce': latest_block.get('Nonce', 0),
                'Timestamp': latest_block.get('Timestamp', 0) # Додамо час блоку
            }
        else:
            print("Колекція BlockChain порожня. Використовуємо нульові значення для першого блоку.")
            # Повертаємо нульові значення для першого блоку, як у ЛР1
            return {
                '_id': None, # Для першого блоку ID документа немає
                'BlockChainHash': "0" * 64,
                'Nonce': 0,
                'Timestamp': 0
            }

    except Exception as e:
        print(f"Помилка при отриманні даних останнього блоку: {e}")
        return None


def perform_mining(transaction):
    """
    Виконує процес майнінгу для заданої транзакції.
    Шукає Nonce, щоб хеш блоку починався з нуля.
    Повертає результати майнінгу або None у випадку помилки/відсутності транзакції.
    """
    if transaction is None:
        print("Не можна виконати майнінг: транзакція відсутня.")
        return None

    # Отримуємо дані останнього блоку
    latest_block_data = get_latest_blockchain_data()
    if latest_block_data is None:
        print("Не вдалося отримати дані останнього блоку для майнінгу.")
        return None

    blockchain_hash_from_previous_block = latest_block_data.get('BlockChainHash', "0" * 64)
    current_nonce = 0
    difficulty_target_prefix = '0' # Ціль: хеш починається з нуля

    print(f"\nПочаток майнінгу для транзакції {transaction.get('TAID', 'N/A')}...")
    start_time = time.time()

    found_nonce = None
    new_blockchain_hash = None
    attempts = 0

    # Цикл майнінгу
    while True:
        attempts += 1
        # Формуємо дані для хешування блоку:
        # Хеш транзакції + BlockChainHash попереднього блоку + поточний Nonce майнінгу
        data_to_hash = (
            transaction.get('TAHash', '') + # Використовуємо хеш транзакції
            blockchain_hash_from_previous_block +
            str(current_nonce)
        )

        # Обчислюємо хеш блоку
        new_blockchain_hash = hash_data_keccak256(data_to_hash.encode('utf-8'))

        # Перевіряємо умову складності
        if new_blockchain_hash.startswith(difficulty_target_prefix):
            found_nonce = current_nonce
            break # Знайдено потрібний Nonce, виходимо з циклу

        # Збільшуємо Nonce
        current_nonce += 1

        # Обмеження для тестування (щоб не працювало вічно, якщо щось піде не так)
        # if attempts > 1000000:
        #     print("Перевищено ліміт спроб майнінгу. Можливо, проблема з Difficulty Target або алгоритмом.")
        #     return None

    end_time = time.time()
    mining_duration = end_time - start_time

    print(f"\nМайнінг успішно завершено!")
    print(f"  Знайдено Nonce: {found_nonce}")
    print(f"  Отримано BlockChainHash (починається з '{difficulty_target_prefix}'): {new_blockchain_hash}")
    print(f"  Час майнінгу: {mining_duration:.4f} секунд")
    print(f"  Кількість спроб (Nonce): {attempts}")

    # Повертаємо результати майнінгу, включаючи хеш попереднього блоку, ID транзакції та об'єкт транзакції
    return {
        'mined_transaction': transaction, # Повертаємо весь об'єкт транзакції
        'previous_block_hash': blockchain_hash_from_previous_block,
        'new_blockchain_hash': new_blockchain_hash,
        'mined_nonce': found_nonce,
        'mining_duration': mining_duration,
        'attempts': attempts,
        'timestamp': int(time.time()) # Додамо час знаходження блоку
    }


def update_wallet_balances(transaction: dict):
    """
    Оновлює баланси гаманців відправника та отримувача для підтвердженої транзакції.
    """
    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних для оновлення балансів.")
        return False

    # Перевірка наявності всіх необхідних полів у транзакції
    required_fields = ['TAID', 'From', 'To', 'TASUM']
    if not all(field in transaction and transaction[field] is not None for field in required_fields):
        print(f"Помилка: Недостатньо даних у транзакції {transaction.get('TAID', 'N/A')} для оновлення балансів.")
        return False

    sender_id = transaction['From']
    recipient_id = transaction['To']
    amount = transaction['TASUM']

    # Оновлення балансів
    try:
        # Зменшуємо баланс відправника
        update_sender_result = db.EWallet.update_one(
            {'CNUCoinID': sender_id},
            {'$inc': {'Balance': -amount}}
        )
        if update_sender_result.modified_count > 0:
             print(f"Баланс відправника {sender_id} зменшено на {amount}.")
        else:
             print(f"Попередження: Баланс відправника {sender_id} не оновлено (можливо, ID не знайдено).")


        # Збільшуємо баланс отримувача
        update_recipient_result = db.EWallet.update_one(
            {'CNUCoinID': recipient_id},
            {'$inc': {'Balance': amount}}
        )
        if update_recipient_result.modified_count > 0:
            print(f"Баланс отримувача {recipient_id} збільшено на {amount}.")
        else:
             print(f"Попередження: Баланс отримувача {recipient_id} не оновлено (можливо, ID не знайдено).")


        print(f"Баланси гаманців оновлено для транзакції {transaction['TAID']}.")
        return True
    except Exception as e:
        print(f"Помилка при оновленні балансів гаманців для транзакції {transaction.get('TAID', 'N/A')}: {e}")
        return False


def save_mined_block(mining_results: dict, miner_id: str):
    """
    Зберігає дані щойно знайденого блоку до колекції BlockChain,
    підписує їх ЕЦП майнера, оновлює статус транзакції на підтверджену
    (включаючи Nonce з майнінгу) та оновлює баланси гаманців.
    Повертає ID збереженого блоку у випадку повного успіху, інакше False.
    """
    if mining_results is None:
        print("Не можна обробити результати майнінгу: результати відсутні.")
        return False

    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних для збереження блоку та оновлення транзакції.")
        return False

    # Отримуємо приватний ключ майнера
    miner_private_key = get_private_key(miner_id)
    if miner_private_key is None:
        print(f"Помилка: Не вдалося отримати приватний ключ для майнера {miner_id}.")
        return False

    # Формуємо дані блоку для збереження та підпису
    block_data_to_save = {
        'BlockChainHash': mining_results.get('new_blockchain_hash'),
        'PreviousBlockHash': mining_results.get('previous_block_hash'),
        'Nonce': mining_results.get('mined_nonce'),
        'MinedTransactionId': mining_results.get('mined_transaction', {}).get('TAID'),
        'MinerId': miner_id,
        'Timestamp': mining_results.get('timestamp'),
        'MinerSignature': None
    }

    # Перевірка наявності критично важливих даних перед підписом та збереженням
    if not all([block_data_to_save['BlockChainHash'], block_data_to_save['Nonce'], block_data_to_save['MinedTransactionId'], block_data_to_save['PreviousBlockHash']]):
         print("Помилка: Недостатньо даних у результатах майнінгу для формування блоку.")
         return False


    # Формуємо рядок для підпису даних блоку
    data_string_to_sign_block = (
        str(block_data_to_save['BlockChainHash']) +
        str(block_data_to_save['Nonce']) +
        str(block_data_to_save['MinedTransactionId']) +
        str(block_data_to_save['PreviousBlockHash'])
    )

    # Підписуємо дані блоку приватним ключем майнера
    try:
        signature_bytes = sign_data_rsa(miner_private_key, data_string_to_sign_block.encode('utf-8'))
        block_data_to_save['MinerSignature'] = signature_bytes.hex()
        print(f"Дані блоку {block_data_to_save['BlockChainHash']} підписано майнером {miner_id}.")
    except Exception as e:
        print(f"Помилка при підписанні даних блоку: {e}.")
        return False # Повертаємо False, якщо підпис не вдався

    # Зберігаємо дані блоку у колекції BlockChain
    try:
        insert_block_result = db.BlockChain.insert_one(block_data_to_save)
        saved_block_id = insert_block_result.inserted_id
        print(f"Блок з хешем {block_data_to_save['BlockChainHash']} успішно збережено з ID: {saved_block_id}.")
    except Exception as e:
        print(f"Помилка при збереженні блоку: {e}")
        return False # Повертаємо False, якщо збереження блоку не вдалocя

    # Оновлюємо статус транзакції та оновлюємо баланси - тільки якщо блок збережено
    mined_transaction = mining_results.get('mined_transaction')
    if not mined_transaction:
        print("Попередження: Результати майнінгу не містять об'єкта транзакції для обробки.")
        return False

    transaction_id = mined_transaction.get('TAID')
    mined_nonce = mining_results.get('mined_nonce') # Отримуємо Nonce, знайдений майнером

    if not transaction_id or mined_nonce is None: # Перевіряємо наявність ID транзакції та знайденого Nonce
        print("Попередження: Недостатньо даних для оновлення транзакції (відсутній TAID або mined_nonce).")
        return False

    try:
        # Оновлюємо документ транзакції: встановлюємо TAApproved = True, Nonce = mined_nonce та посилання на блок
        update_transaction_result = db.Transactions.update_one(
            {'TAID': transaction_id},
            {
                '$set': {
                    'TAApproved': True,
                    'Nonce': mined_nonce,
                    'MinedInBlock': saved_block_id
                }
            }
        )
        if update_transaction_result.modified_count == 0:
             print(f"Попередження: Статус транзакції {transaction_id} не оновлено (можливо, ID не знайдено або вже підтверджено).")
             return False

    except Exception as e:
       print(f"Помилка при оновленні статусу транзакції {transaction_id}: {e}")
       return False

    # Оновлюємо баланси гаманців для підтвердженої транзакції
    if update_wallet_balances(mined_transaction):
        # Успіх всіх етапів! Повертаємо ID збереженого блоку.
        print(f"Баланси гаманців оновлено для транзакції {transaction_id}.")
        return saved_block_id
    else:
        print(f"Помилка при оновленні балансів для транзакції {transaction_id}.")
        return False


def get_unconfirmed_transaction():
    """
    Вибирає першу за датою/часом непідтверджену транзакцію з бази даних.
    """
    db = connect_db()
    if db is None:
        print("Не вдалося підключитися до бази даних для отримання непідтвердженої транзакції.")
        return None

    try:
        # Шукаємо транзакцію, де TAApproved є False
        # Сортуємо за датою (TADate) за зростанням (1)
        # Обмежуємо результат одним документом (перша транзакція)
        unconfirmed_transaction = db.Transactions.find_one(
            {'TAApproved': False},
            sort=[('TADate', 1)]
        )

        if unconfirmed_transaction:
            print(f"Знайдено непідтверджену транзакцію: {unconfirmed_transaction.get('TAID', 'N/A')}")
            return unconfirmed_transaction
        else:
            print("Не знайдено непідтверджених транзакцій.")
            return None

    except Exception as e:
        print(f"Помилка при отриманні непідтвердженої транзакції: {e}")
        return None


# Приклад використання
if __name__ == "__main__":
    # Спочатку отримуємо непідтверджену транзакцію для майнінгу
    transaction_to_mine = get_unconfirmed_transaction()

    if transaction_to_mine:
        # Якщо транзакцію знайдено, виконуємо майнінг
        mining_results = perform_mining(transaction_to_mine)

        if mining_results:
            print("\nРезультати майнінгу:")
            print(mining_results)

            # 5. Зберігаємо знайдений блок, підписуємо його майнером, оновлюємо транзакцію та баланси

            miner_real_id = "9ee2ad2d63a5a2b4bde1e85b9758f3f3417d79ad741e92156645d40edb9f4681"

            print(f"\nСпроба збереження блоку, підписання майнером {miner_real_id}, оновлення транзакції та балансів.")
            saved_block_id = save_mined_block(mining_results, miner_real_id)

            if saved_block_id:
                print(f"\nБлок успішно збережено, транзакція підтверджена та баланси оновлені.")
            else:
                print("\nНе вдалося повністю обробити знайдений блок (збереження, підпис, оновлення транзакції/балансів).")
        else:
            print("\nМайнінг не був успішним.")
    else:
        print("\nНемає транзакцій для майнінгу. Створіть транзакцію за допомогою transaction.py")