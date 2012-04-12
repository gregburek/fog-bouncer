require "helper"

describe Fog::Bouncer::Sources::CIDR do
  subject { Fog::Bouncer::Sources::CIDR }

  it "only supports valid CIDR ranges" do
    lambda { subject.new("1234.5678.9012.3456/999999", nil) }.must_raise(ArgumentError)
  end
end
