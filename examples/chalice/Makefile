deploy:
	cp -af ../../pywarp vendor
	chalice --version
	PYTHONPATH=$$PYTHONPATH:vendor chalice deploy
