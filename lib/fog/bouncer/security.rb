module Fog
  module Bouncer
    class Security
      attr_reader :name, :description

      def initialize(name, &block)
        @name = name
        instance_eval(&block)
      end

      def accounts
        @accounts ||= { 'amazon-elb' => 'amazon-elb', 'self' => Fog::Bouncer.aws_account_id }
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

      def clear_remote
        GroupManager.new(self).clear
      end

      private

      def account(name, account_id)
        accounts[name] = account_id
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
