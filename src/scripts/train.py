import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump
from src.scripts import config
from src.scripts.preprocess import preprocess


def train():
    model = IsolationForest(random_state=config.RANDOM_STATE)
    train_data = pd.read_csv(config.DATA_TRAIN_PATH)
    processed_data = preprocess(train_data)
    model.fit(processed_data)
    using_model = input('Use default model? (y/n): ').strip().lower()
    name_model = 'model' if using_model == 'y' else input('Input model name: ').strip()

    dump(model, 'src/models/{}.joblib'.format(name_model))
