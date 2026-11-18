VENV := .venv
VENV_BIN := $(VENV)/bin
SETUP_CLI := $(VENV_BIN)/admiral-detector-setup

.PHONY: help venv setup setup-detector setup-pihole-sync setup-all uninstall uninstall-pihole-sync purge clean

help:
	@echo "Available targets:"
	@echo "  make venv                    Create .venv and install admiral_detector in editable mode"
	@echo "  sudo make setup              Interactive systemd and Pi-hole sync setup"
	@echo "  sudo make setup-detector     Non-interactive core detector service setup only"
	@echo "  sudo make setup-pihole-sync  Non-interactive Pi-hole sync integration setup only"
	@echo "  sudo make setup-all          Non-interactive full setup (detector + Pi-hole sync)"
	@echo "  sudo make uninstall          Remove services and Pi-hole integration (keeps config/data)"
	@echo "  sudo make uninstall-pihole-sync  Remove Pi-hole sync integration only"
	@echo "  sudo make purge              Remove services, Pi-hole integration, config, data, and user"
	@echo "  make clean                   Remove Python build artifacts"

venv:
	@if [ ! -x "$(SETUP_CLI)" ]; then \
		python3 -m venv "$(VENV)"; \
		"$(VENV_BIN)/pip" install --upgrade pip >/dev/null; \
		"$(VENV_BIN)/pip" install -e .; \
		if [ -n "$$SUDO_USER" ]; then \
			chown -R "$$SUDO_USER:$$(id -gn "$$SUDO_USER")" "$(VENV)"; \
		fi; \
	fi

setup: venv
	@sudo "$(SETUP_CLI)"

setup-detector: venv
	@sudo "$(SETUP_CLI)" -y --without-pihole-sync

setup-pihole-sync: venv
	@sudo "$(SETUP_CLI)" -y --pihole-sync-only

setup-all: venv
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
	else \
		echo "Error: $(SETUP_CLI) not found." >&2; \
		exit 1; \
	fi

clean:
	rm -rf build dist *.egg-info src/*.egg-info