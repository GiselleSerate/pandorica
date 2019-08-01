# Activate venv
source .env/bin/activate

echo Triggering parse script.
python src/notes_parser.py

echo Triggering aggregate script.
python src/aggregator.py
exit 0
