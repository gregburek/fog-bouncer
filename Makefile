VERSION=$(shell ruby -r./lib/fog/bouncer/version -e "puts Fog::Bouncer::VERSION")

# default the projcet name to the directory name
PROJECT?=$(notdir $(PWD))
GEM=$(PROJECT)-$(VERSION).gem

.PHONY: test
test:
	bundle exec rake test

.PHONY: package
package: $(GEM)

# Always build the gem
.PHONY: $(GEM)
$(GEM):
	gem build $(PROJECT).gemspec

.PHONY: install
install: $(GEM)
	gem install $<

# Publish to gemgate
.PHONY: publish
publish: $(GEM)
	 gem push $(GEM)
