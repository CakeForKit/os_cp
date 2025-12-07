# Python скрипт для обработки больших данных
import numpy as np
import pandas as pd

# Создаем большой DataFrame
df = pd.DataFrame(np.random.randn(10000000, 100))  # 10M строк × 100 колонок
result = df.groupby(df.index % 1000).mean()