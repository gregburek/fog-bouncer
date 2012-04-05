module Fog
  module Bouncer
    class DefinitionNotFound < StandardError; end
    class SourceBlockRequired < StandardError; end
    class Security
      attr_reader :name, :description

      def initialize(name, &block)
        @name = name
        @definitions = {}
        @using = []
        instance_eval(&block)
        apply_definitions
      end

      def accounts
        @accounts ||= { 'amazon-elb' => 'amazon-elb', 'self' => Fog::Bouncer.aws_account_id }
      end

      def define(name, source, &block)
        raise SourceBlockRequired unless block_given?
        @definitions[name] = { source: source, block: block }
      end

      def definitions(name)
        @definitions[name] || raise(DefinitionNotFound.new("No definition found for #{name}."))
      end

      def extra_remote_groups
        groups.select { |group| !group.local? && group.remote? }
      end

      def groups
        @groups ||= []
      end

      def import_remote_groups
        Fog::Bouncer.fog.security_groups.each do |remote_group|
          group = group(remote_group.name, remote_group.description)
          group.remote = remote_group
          IPPermissions.to(group, remote_group.ip_permissions) if remote_group.ip_permissions
        end
      end

      def missing_remote_groups
        groups.select { |group| group.local? && !group.remote? }
      end

      def sync
        GroupManager.new(self).synchronize
      end

      def use(name)
        @using << definitions(name)
      end

      def clear_remote
        GroupManager.new(self).clear
      end

      private

      def account(name, account_id)
        accounts[name] = account_id
      end

      def apply_definitions
        return if @using.empty?

        @using.each do |definition|
          @groups.each do |group|
            group.add_source(definition[:source], &definition[:block])
          end
        end
      end

      def group(name, description, &block)
        group = groups.find { |group| group.name == name }
        if group.nil?
          group = Group.new(name, description, self, &block)
          groups << group
        end

        group
      end
    end
  end
end
