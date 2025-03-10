from src.scripts import train, config, PacketAnalyzer
from joblib import load
import warnings
import argparse

warnings.filterwarnings("ignore", category=UserWarning)


def main(mode, duration=config.DURATION, file_path=None):
    train.train()
    mode = False if mode == 'False' else True
    model = load(config.MODEL_PATH)
    analyzer = PacketAnalyzer.PacketAnalyzer(mode, model, duration, file_record_path=config.FILE_RECORD)
    if file_path:
        analyzer.analyze_file(file_path)
    else:
        analyzer.capture()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Packet analyzer')

    parser.add_argument('--duration', type=int, default=10, help='Duration for live packet capturing (default: 10)')
    parser.add_argument('--file', type=str, help='Path to the file for analysis')
    parser.add_argument('--file_record', type=str, help='Path to the file for record')
    parser.add_argument('--analyze', type=bool, default='True', help='Analysis or capture mode')

    args = parser.parse_args()

    main(mode=args.analyze, duration=args.duration, file_path=args.file)