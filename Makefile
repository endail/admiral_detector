VENV := /opt/admiral_detector/.venv
VENV_BIN := $(VENV)/bin
SETUP_CLI := $(VENV_BIN)/admiral-detector-setup

.PHONY: help install-venv setup setup-detector setup-pihole-sync setup-all uninstall uninstall-pihole-sync purge clean

help:
	@echo "Available targets:"
	@echo "  sudo make setup                  Interactive systemd and Pi-hole sync setup"
	@echo "  sudo make setup-detector         Non-interactive core detector service setup only"
	@echo "  sudo make setup-pihole-sync      Non-interactive Pi-hole sync integration setup only"
	@echo "  sudo make setup-all              Non-interactive full setup (detector + Pi-hole sync)"
	@echo "  sudo make uninstall              Remove services and Pi-hole integration (keeps config/data)"
	@echo "  sudo make uninstall-pihole-sync  Remove Pi-hole sync integration only"
	@echo "  sudo make purge                  Remove services, Pi-hole integration, config, data, user, and venv"
	@echo "  make clean                       Remove local Python build artifacts"

install-venv:
	@if [ ! -x "$(VENV_BIN)/python" ]; then \
		sudo mkdir -p /opt/admiral_detector; \
		sudo python3 -m venv "$(VENV)"; \
	fi
	@sudo "$(VENV_BIN)/pip" install --upgrade pip >/dev/null
	@sudo "$(VENV_BIN)/pip" install --upgrade .
	@sudo chmod -R a+rX /opt/admiral_detector

setup: install-venv
	@sudo "$(SETUP_CLI)"

setup-detector: install-venv
	@sudo "$(SETUP_CLI)" -y --without-pihole-sync

setup-pihole-sync: install-venv
	@sudo "$(SETUP_CLI)" -y --pihole-sync-only

setup-all: install-venv
	@sudo "$(SETUP_CLI)" -y --with-pihole-sync

uninstall:
	@if [ -x "$(SETUP_CLI)" ]; then \
		sudo "$(SETUP_CLI)" -y --uninstall; \
	else \
		echo "Error: $(SETUP_CLI) not found." >&2; \
		exit 1; \
	fi

uninstall-pihole-sync:
	@if [ -x "$(SETUP_CLI)" ]; then \
		sudo "$(SETUP_CLI)" -y --uninstall-pihole-sync; \
	else \
		echo "Error: $(SETUP_CLI) not found." >&2; \
		exit 1; \
	fi

purge:
	@if [ -x "$(SETUP_CLI)" ]; then \
		sudo "$(SETUP_CLI)" -y --purge; \
	fi
	@sudo rm -rf /opt/admiral_detector

clean:
	rm -rf build dist *.egg-info src/*.egg-info