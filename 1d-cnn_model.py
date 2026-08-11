import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

# ======================
# 1. Загрузка и подготовка данных
# ======================
# Предполагается, что данные находятся в CSV-файле с колонками 'text' и 'label'
# Если файла нет, создадим примерный датасет для демонстрации
try:
    df = pd.read_csv('phishing_emails.csv')
    texts = df['text'].astype(str).values
    labels = df['label'].values
except FileNotFoundError:
    print("Файл 'phishing_emails.csv' не найден. Создаю синтетический датасет...")
    # Синтетические данные (10 образцов для примера)
    texts = np.array([
        "Ваш аккаунт заблокирован, перейдите по ссылке для разблокировки",
        "Подтвердите свои данные, иначе доступ будет ограничен",
        "Вы выиграли приз! Заполните форму",
        "Уведомление о безопасности от вашего банка",
        "Важное сообщение от службы поддержки PayPal",
        "Счет на оплату № 3421",
        "Напоминание о встрече завтра в 10:00",
        "Новый пароль для входа в систему",
        "Спам-рассылка от неизвестного отправителя",
        "Легитимное письмо от HR отдела",
        "мяу"
    ])
    labels = np.array([1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0])  # 1 - фишинг, 0 - не фишинг

# Кодирование меток (если они в текстовом формате)
if labels.dtype == object:
    le = LabelEncoder()
    labels = le.fit_transform(labels)

# Разделение на обучающую и тестовую выборки
X_train, X_test, y_train, y_test = train_test_split(
    texts, labels, test_size=0.2, random_state=42, stratify=labels
)

# ======================
# 2. Токенизация и приведение к одинаковой длине
# ======================
MAX_VOCAB_SIZE = 10000   # Размер словаря
MAX_SEQUENCE_LEN = 200    # Максимальная длина текста (усекаем или дополняем)

tokenizer = Tokenizer(num_words=MAX_VOCAB_SIZE, oov_token='<OOV>')
tokenizer.fit_on_texts(X_train)

# Преобразование текстов в последовательности индексов
X_train_seq = tokenizer.texts_to_sequences(X_train)
X_test_seq = tokenizer.texts_to_sequences(X_test)

# Padding (выравнивание длины)
X_train_pad = pad_sequences(X_train_seq, maxlen=MAX_SEQUENCE_LEN, padding='post', truncating='post')
X_test_pad = pad_sequences(X_test_seq, maxlen=MAX_SEQUENCE_LEN, padding='post', truncating='post')

# ======================
# 3. Построение модели 1D-CNN
# ======================
EMBEDDING_DIM = 200      # Размерность эмбеддингов
NUM_FILTERS = 64        # Количество фильтров свёртки
KERNEL_SIZE = 5          # Размер ядра свёртки
DROPOUT_RATE = 0.5

model = Sequential([
    Embedding(input_dim=MAX_VOCAB_SIZE, output_dim=EMBEDDING_DIM, input_length=MAX_SEQUENCE_LEN),
    Conv1D(filters=NUM_FILTERS, kernel_size=KERNEL_SIZE, activation='relu'),
    GlobalMaxPooling1D(),            # Субдискретизация
    Dense(64, activation='relu'),
    Dropout(DROPOUT_RATE),
    Dense(1, activation='sigmoid')   # Бинарная классификация
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

model.summary()

# ======================
# 4. Обучение модели
# ======================
EARLY_STOP_PATIENCE = 3
BATCH_SIZE = 32
EPOCHS = 10

early_stop = EarlyStopping(monitor='val_loss', patience=EARLY_STOP_PATIENCE, restore_best_weights=True)

history = model.fit(
    X_train_pad, y_train,
    batch_size=BATCH_SIZE,
    epochs=EPOCHS,
    validation_split=0.2,
    callbacks=[early_stop],
    verbose=1
)

# ======================
# 5. Оценка модели
# ======================
y_pred_prob = model.predict(X_test_pad)
y_pred = (y_pred_prob > 0.5).astype(int).flatten()

print("\n=== Результаты на тестовой выборке ===")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(classification_report(y_test, y_pred, target_names=['Не фишинг', 'Фишинг']))

# ======================
# 6. Пример предсказания для нового текста
# ======================
def predict_phishing(text):
    seq = tokenizer.texts_to_sequences([text])
    padded = pad_sequences(seq, maxlen=MAX_SEQUENCE_LEN, padding='post', truncating='post')
    prob = model.predict(padded)[0][0]
    return "Фишинг" if prob > 0.5 else "Не фишинг", prob

new_texts = [
    "Срочно! Ваша учетная запись будет удалена, перейдите по ссылке для подтверждения",
    "Здравствуйте, направляем вам отчет по проекту за прошлый месяц",
    "Кереешке по скидке здесь",
    "тестовый текст, аккуратненький такой, не спеша, черемша",
    "Восстановелние аккаунта",
    "Жоское что-то видео там гитхаб хз"
]

for t in new_texts:
    label, prob = predict_phishing(t)
    print(f"\nТекст: {t}\nКласс: {label} (вероятность фишинга: {prob:.4f})")