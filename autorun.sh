# Activate venv
source .env/bin/activate

# Check if proper docker is running
if (docker ps | grep myelk_con > /dev/null 2>&1); then
	echo Triggering parse script.
	python src/parser.py
	exit 0
else
	echo Please start the elk docker container and try again.
	exit 1
fi
