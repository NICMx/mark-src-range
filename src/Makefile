PROJECTS = mod usr
OTHER_TARGETS = install clean


all: $(PROJECTS)
	# Ok, done.
$(PROJECTS):
	$(MAKE) -C $@
$(OTHER_TARGETS):
	$(foreach dir, $(PROJECTS), $(MAKE) -C $(dir) $@;)


.PHONY: $(PROJECTS) $(OTHER_TARGETS)

