from src.scripts import config

def preprocess(data):
    data = data.iloc[:, 1:]
    if data.shape[0] != config.TRAIN_DATA_SIZE:
        data = data.drop_duplicates()
        data = data.loc[~(data == 0).all(axis=1)]
        data = data.apply(lambda x: x.round(4))

        columns = list(data.columns)
        data[columns] = data[columns].astype('float64')

        for column in columns:
            data[column].fillna(value=data[column].mean())

        return data

