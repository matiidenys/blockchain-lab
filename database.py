from pymongo import MongoClient

# Конфігурація підключення до MongoDB
MONGO_HOST = 'localhost'
MONGO_PORT = 27017
DATABASE_NAME = 'CNUCoinDB' # Назва бази даних

def connect_db():
    try:
        client = MongoClient(MONGO_HOST, MONGO_PORT)
        db = client[DATABASE_NAME]
        print(f"Підключено до бази даних: {DATABASE_NAME}")
        return db
    except Exception as e:
        print(f"Помилка підключення до MongoDB: {e}")
        return None

# Використовувалась 1 раз на початку, щоб створити колекції
def create_collections(db):
    """Створює необхідні колекції у базі даних, якщо вони не існують."""
    collections = [
        'CnuCoinMembers',  # Таблиця реєстрації учасників [cite: 40]
        'Transactions',      # Таблиця транзакцій [cite: 40]
        'BlockChain',      # Таблиця для збереження хеш-образу Block Chain [cite: 40]
        'Private',         # Таблиця для збереження ключів [cite: 40]
        'EWallet'          # Електронний гаманець [cite: 40]
    ]

    for col_name in collections:
        if col_name not in db.list_collection_names():
            db.create_collection(col_name)
            print(f"Колекцію '{col_name}' створено.")
        else:
            print(f"Колекція '{col_name}' вже існує.")

if __name__ == "__main__":
    db = connect_db()
    # if db is not None:
    #     create_collections(db)