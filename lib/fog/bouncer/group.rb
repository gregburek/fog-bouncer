module Fog
  module Bouncer
    class Group
      attr_reader :name, :description, :security
      attr_accessor :local, :remote

      def self.log(data, &block)
        Fog::Bouncer.log({ group: true }.merge(data), &block)
      end

      def log(data, &block)
        self.class.log({ name: name }.merge(data), &block)
      end

      def initialize(name, description, security, &block)
        @name = name
        @description = description
        @security = security
        if block_given?
          @local = true
          instance_eval(&block)
        end
      end

      def extra_remote_sources
        sources.select { |source| !source.local? && source.remote? }
      end

      def local?
        !!local
      end

      def missing_remote_sources
        sources.select { |source| source.local? && !source.remote? }
      end

      def remote?
        !remote.nil?
      end

      def sources
        @sources ||= []
      end

      def sync
        log(sync: true) do
          create_missing_remote
          synchronize_sources
        end
      end

      def create_missing_remote
        unless remote?
          log(create_missing_remote: true) do
            @remote = Fog::Bouncer.fog.security_groups.create(:name => name, :description => description)
            @remote.reload
          end
        end
      end

      def synchronize_sources
        log(synchronize_sources: true) do
          SourceManager.new(self).synchronize
        end
      end

      def destroy
        revoke
        if remote?
          if name != "default"
            log(destroy: true) do
              remote.destroy
              @remote = nil
              @security.groups.delete_if { |g| g.name == name }
            end
          else
            log(destroy: false, group_name: name)
          end
        end
      end

      def revoke
        permissions = sources.map do |source|
          source.protocols.select { |p| p.remote? }
        end.flatten.compact

        if remote? && permissions.any?
          log(revoke: true) do
            remote.connection.revoke_security_group_ingress(name, "IpPermissions" => IPPermissions.from(permissions))
            permissions.each do |protocol|
              log({revoked: true}.merge(protocol.to_log))
              protocol.source.protocols.delete_if { |p| p == protocol }
            end
          end
        end
      end

      def ==(other)
        name == other.name &&
        description == other.description
      end

      def inspect
        "<#{self.class.name} @name=#{name.inspect} @description=#{description.inspect} @local=#{local} @remote=#{remote} @sources=#{sources.inspect}>"
      end

      private

      def source(source, &block)
        if existing = sources.find { |s| s.match(source) }
          existing.instance_eval(&block)
        else
          sources << Sources.for(source, self, &block)
        end
      end
    end
  end
end
