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

      def from_ip_permissions(ip_permissions)
        ip_permissions.each do |permission|
          remote_sources = []
          remote_sources = remote_sources | permission["groups"].collect { |group| "#{group["groupName"]}@#{group["userId"]}" }
          remote_sources = remote_sources | permission["ipRanges"].collect { |range| range["cidrIp"] }
          remote_sources.each do |s|
            source = existing_source_for(s)
            if source.nil?
              source = Sources.for(s, self)
              sources << source
            end
            source.remote = true
            source.from_ip_protocol(permission["ipProtocol"], permission["fromPort"], permission["toPort"])
          end
        end
      end

      def remote?
        !remote.nil?
      end

      def sources
        @sources ||= []
      end

      def sources=(sources)
        @sources = sources
      end

      def ==(other)
        name == other.name &&
        description == other.description
      end

      def inspect
        "<#{self.class.name} @name=#{name.inspect} @description=#{description.inspect} @local=#{local} @remote=#{remote} @sources=#{sources.inspect}>"
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
        permissions = IPPermissions.from(sources.collect { |s| s.protocols }.flatten.compact, :remote => true)
        if remote? && permissions.any?
          log(revoke: true) do
            remote.connection.revoke_security_group_ingress(name, "IpPermissions" => permissions)
            @sources = []
          end
        end
      end

      private

      def existing_source_for(source)
        case source
        when /^\d+\.\d+\.\d+.\d+\/\d+$/
          sources.find { |s| source == s.source }
        when /^(.+)@(.+)$/
          sources.find { |s| source == "#{s.name}@#{s.user_id}"}
        when /^@(.+)$/
          sources.find { |s| source == "@#{s.user_id}"}
        else
          sources.find { |s| source == s.source }
        end
      end

      def source(source, &block)
        if existing = existing_source_for(source)
          existing.instance_eval(&block)
        else
          sources << Sources.for(source, self, &block)
        end
      end
    end
  end
end
