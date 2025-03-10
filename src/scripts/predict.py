from src.scripts import config


def analyze_data(model, data):
    data = data[1:]
    if data.size != config.TRAIN_DATA_SIZE:
        raise ValueError("Incorrect input data size")

    return model.predict([data])[0]
